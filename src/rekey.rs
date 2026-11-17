//! In-band rekey: fresh X25519 + ML-KEM-1024, new keys and epoch.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::error::Error;
use crate::handshake::VERSION;
use crate::keys::{ServerKeys, ServerPublicKeys, random_bytes, verify_server_signatures};
use crate::nmtb::{self, Value};
use crate::session::Session;
use crate::util::check_timestamp;

pub const REKEY_DOMAIN: &[u8] = b"NMT/v2/rekey\0";

/// Client state between a rekey request and response.
pub struct RekeyClient {
    unsigned: Vec<u8>,
    x_private: StaticSecret,
    mlkem_private: <MlKem1024 as Kem>::DecapsulationKey,
    client_nonce: Vec<u8>,
    server_keys: ServerPublicKeys,
    session_id: [u8; 16],
    epoch: u64,
    now_ms: i64,
}

/// Response plus the next key set. The caller seals the response with the old
/// keys, then calls `Session::rotate`.
pub struct RekeyResult {
    pub response: Value,
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

impl RekeyClient {
    /// Build a rekey payload. It must be sealed as a request with method
    /// `session.rekey`.
    pub fn new(
        session: &Session,
        server_keys: ServerPublicKeys,
        now_ms: i64,
    ) -> Result<(Self, Value), Error> {
        let x_private = StaticSecret::from(random_array::<32>()?);
        let x_public = X25519PublicKey::from(&x_private);
        let (mlkem_private, mlkem_public) = MlKem1024::generate_keypair();
        let client_nonce = random_bytes(32)?;
        let epoch = session.epoch();

        let mut map = BTreeMap::new();
        map.insert("version".into(), Value::Int(VERSION));
        map.insert("epoch".into(), Value::Int(epoch as i64));
        map.insert("client_nonce".into(), Value::Bytes(client_nonce.clone()));
        map.insert(
            "client_x25519".into(),
            Value::Bytes(x_public.as_bytes().to_vec()),
        );
        map.insert(
            "client_mlkem".into(),
            Value::Bytes(mlkem_public.to_bytes().as_slice().to_vec()),
        );
        map.insert("timestamp".into(), Value::Int(now_ms));
        let value = Value::Map(map);
        let unsigned = nmtb::marshal(&value)?;

        Ok((
            Self {
                unsigned,
                x_private,
                mlkem_private,
                client_nonce,
                server_keys,
                session_id: session.id,
                epoch,
                now_ms,
            },
            value,
        ))
    }

    /// Verify a rekey response and rotate local session keys.
    pub fn finish(&mut self, session: &mut Session, response: &Value) -> Result<(), Error> {
        if session.epoch() != self.epoch {
            return Err(Error::Message("session epoch changed during rekey".into()));
        }
        let map = response
            .as_map()
            .ok_or_else(|| Error::Message("invalid rekey response".into()))?;
        let version = map_int(map, "version")?;
        if version != VERSION {
            return Err(Error::Handshake("unsupported version".into()));
        }
        let server_nonce = map_bytes(map, "server_nonce", 32, 32)?;
        let server_x25519 = map_bytes(map, "server_x25519", 32, 32)?;
        let mlkem_ciphertext = map_bytes(map, "mlkem_ciphertext", 1, 4096)?;
        let timestamp = map_int(map, "timestamp")?;
        check_timestamp(self.now_ms, timestamp)?;
        let secp_signature = map_bytes(map, "signature_secp256k1", 1, 128)?;
        let mldsa_signature = map_bytes(map, "signature_mldsa", 1, 8192)?;
        let session_id = map_bytes(map, "session_id", 16, 16)?;
        let epoch = map_int(map, "epoch")?;
        if epoch != self.epoch as i64 {
            return Err(Error::Message("rekey epoch mismatch".into()));
        }
        if session_id.as_slice() != self.session_id.as_slice() {
            return Err(Error::Message("rekey session id mismatch".into()));
        }

        let mut server_map = BTreeMap::new();
        server_map.insert("version".into(), Value::Int(version));
        server_map.insert("server_nonce".into(), Value::Bytes(server_nonce.clone()));
        server_map.insert("server_x25519".into(), Value::Bytes(server_x25519.clone()));
        server_map.insert(
            "mlkem_ciphertext".into(),
            Value::Bytes(mlkem_ciphertext.clone()),
        );
        server_map.insert("timestamp".into(), Value::Int(timestamp));
        let server_unsigned = nmtb::marshal(&Value::Map(server_map))?;
        let transcript = rekey_transcript(
            &self.session_id,
            self.epoch,
            &self.unsigned,
            &server_unsigned,
            &self.client_nonce,
            &server_nonce,
        );
        verify_server_signatures(
            &self.server_keys,
            &transcript,
            &secp_signature,
            &mldsa_signature,
        )?;

        let peer_public = X25519PublicKey::from(array_32(&server_x25519)?);
        let x_shared = self.x_private.diffie_hellman(&peer_public);
        let mlkem_shared = self
            .mlkem_private
            .decapsulate_slice(&mlkem_ciphertext)
            .map_err(|_| Error::Handshake("ml-kem decapsulation failed".into()))?;
        let (c2s, s2c) =
            derive_rekey_keys(x_shared.as_bytes(), mlkem_shared.as_slice(), &transcript)?;
        session.rotate(c2s, s2c, self.now_ms);
        Ok(())
    }
}

/// Process a rekey request and return the response plus the next server keys.
pub fn server_rekey(
    session: &Session,
    request: &Value,
    keys: &ServerKeys,
    now_ms: i64,
) -> Result<RekeyResult, Error> {
    if session.expired(now_ms) {
        return Err(Error::SessionExpired);
    }
    let map = request
        .as_map()
        .ok_or_else(|| Error::Message("invalid rekey request".into()))?;
    let version = map_int(map, "version")?;
    if version != VERSION {
        return Err(Error::Handshake("unsupported version".into()));
    }
    let request_epoch = map_int(map, "epoch")?;
    let epoch = session.epoch();
    if request_epoch < 0 || request_epoch as u64 != epoch {
        return Err(Error::Message("stale rekey epoch".into()));
    }
    let client_nonce = map_bytes(map, "client_nonce", 32, 32)?;
    let client_x25519 = map_bytes(map, "client_x25519", 32, 32)?;
    let client_mlkem = map_bytes(map, "client_mlkem", 1, 4096)?;
    let timestamp = map_int(map, "timestamp")?;
    check_timestamp(now_ms, timestamp)?;

    let mut client_map = BTreeMap::new();
    client_map.insert("version".into(), Value::Int(version));
    client_map.insert("epoch".into(), Value::Int(request_epoch));
    client_map.insert("client_nonce".into(), Value::Bytes(client_nonce.clone()));
    client_map.insert("client_x25519".into(), Value::Bytes(client_x25519.clone()));
    client_map.insert("client_mlkem".into(), Value::Bytes(client_mlkem.clone()));
    client_map.insert("timestamp".into(), Value::Int(timestamp));
    let client_unsigned = nmtb::marshal(&Value::Map(client_map))?;

    let x_private = StaticSecret::from(random_array::<32>()?);
    let x_public = X25519PublicKey::from(&x_private);
    let client_public = X25519PublicKey::from(array_32(&client_x25519)?);
    let x_shared = x_private.diffie_hellman(&client_public);
    let encapsulation_key =
        <<MlKem1024 as Kem>::EncapsulationKey as TryKeyInit>::new_from_slice(&client_mlkem)
            .map_err(|_| Error::Handshake("client ml-kem key is invalid".into()))?;
    let (mlkem_ciphertext, mlkem_shared) = encapsulation_key.encapsulate();
    let server_nonce = random_bytes(32)?;
    let server_timestamp = now_ms;

    let mut server_map = BTreeMap::new();
    server_map.insert("version".into(), Value::Int(VERSION));
    server_map.insert("server_nonce".into(), Value::Bytes(server_nonce.clone()));
    server_map.insert(
        "server_x25519".into(),
        Value::Bytes(x_public.as_bytes().to_vec()),
    );
    server_map.insert(
        "mlkem_ciphertext".into(),
        Value::Bytes(mlkem_ciphertext.as_slice().to_vec()),
    );
    server_map.insert("timestamp".into(), Value::Int(server_timestamp));
    let server_unsigned = nmtb::marshal(&Value::Map(server_map))?;
    let transcript = rekey_transcript(
        &session.id,
        epoch,
        &client_unsigned,
        &server_unsigned,
        &client_nonce,
        &server_nonce,
    );
    let (secp_signature, mldsa_signature) = keys.sign(&transcript)?;
    let (c2s, s2c) = derive_rekey_keys(x_shared.as_bytes(), mlkem_shared.as_slice(), &transcript)?;

    let mut response = BTreeMap::new();
    response.insert("version".into(), Value::Int(VERSION));
    response.insert("server_nonce".into(), Value::Bytes(server_nonce));
    response.insert(
        "server_x25519".into(),
        Value::Bytes(x_public.as_bytes().to_vec()),
    );
    response.insert(
        "mlkem_ciphertext".into(),
        Value::Bytes(mlkem_ciphertext.as_slice().to_vec()),
    );
    response.insert("timestamp".into(), Value::Int(server_timestamp));
    response.insert("signature_secp256k1".into(), Value::Bytes(secp_signature));
    response.insert("signature_mldsa".into(), Value::Bytes(mldsa_signature));
    response.insert("session_id".into(), Value::Bytes(session.id.to_vec()));
    response.insert("epoch".into(), Value::Int(epoch as i64));
    Ok(RekeyResult {
        response: Value::Map(response),
        send_key: s2c,
        recv_key: c2s,
    })
}

fn rekey_transcript(
    session_id: &[u8; 16],
    epoch: u64,
    client: &[u8],
    server: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        REKEY_DOMAIN.len()
            + session_id.len()
            + 8
            + client.len()
            + server.len()
            + client_nonce.len()
            + server_nonce.len(),
    );
    input.extend_from_slice(REKEY_DOMAIN);
    input.extend_from_slice(session_id);
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(client);
    input.extend_from_slice(server);
    input.extend_from_slice(client_nonce);
    input.extend_from_slice(server_nonce);
    Sha256::digest(input).into()
}

fn derive_rekey_keys(
    x_shared: &[u8],
    mlkem_shared: &[u8],
    transcript: &[u8],
) -> Result<([u8; 32], [u8; 32]), Error> {
    let mut ikm = Vec::with_capacity(x_shared.len() + mlkem_shared.len());
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(mlkem_shared);
    let hkdf = Hkdf::<Sha256>::new(Some(transcript), &ikm);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    hkdf.expand(b"NMT/v2/rekey/c2s", &mut c2s)
        .map_err(|_| Error::Crypto("hkdf rekey c2s".into()))?;
    hkdf.expand(b"NMT/v2/rekey/s2c", &mut s2c)
        .map_err(|_| Error::Crypto("hkdf rekey s2c".into()))?;
    Ok((c2s, s2c))
}

fn map_bytes(
    map: &BTreeMap<String, Value>,
    key: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    let value = map
        .get(key)
        .and_then(Value::as_bytes)
        .ok_or_else(|| Error::Handshake(format!("{key} must be bytes")))?;
    if value.len() < minimum || value.len() > maximum {
        return Err(Error::Handshake(format!("{key} has invalid length")));
    }
    Ok(value.to_vec())
}

fn map_int(map: &BTreeMap<String, Value>, key: &str) -> Result<i64, Error> {
    map.get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| Error::Handshake(format!("{key} must be an integer")))
}

fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    let bytes = random_bytes(N)?;
    Ok(bytes.try_into().expect("random length"))
}

fn array_32(value: &[u8]) -> Result<[u8; 32], Error> {
    value
        .try_into()
        .map_err(|_| Error::Handshake("expected 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::Certificate;
    use crate::handshake::{ClientHandshake, ServerHandshakeOptions, server_handshake};
    use crate::session::{Kind, SessionPolicy};

    fn now() -> i64 {
        1_700_000_000_000
    }

    #[test]
    fn rekey_round_trip() {
        let issuer = ServerKeys::generate().unwrap();
        let leaf = ServerKeys::generate().unwrap();
        let certificate = Certificate::issue(
            &leaf,
            &issuer,
            "server-1",
            now() - 60_000,
            now() + 3_600_000,
        )
        .unwrap()
        .marshal()
        .unwrap();
        let (mut client, request) =
            ClientHandshake::new(issuer.public(), now(), "server-1").unwrap();
        let (response, mut server_session) = server_handshake(
            &request,
            ServerHandshakeOptions {
                keys: &leaf,
                certificate: &certificate,
                replay_seen: None,
                now_ms: now(),
                policy: SessionPolicy::default(),
            },
        )
        .unwrap();
        let mut client_session = client.finish(&response).unwrap();
        client_session.set_clock(now);
        server_session.set_clock(now);

        let (mut rekey, payload) = RekeyClient::new(&client_session, leaf.public(), now()).unwrap();
        let frame = client_session
            .seal(Kind::Request, "session.rekey", 1, &payload)
            .unwrap();
        let opened = server_session.open(&frame).unwrap();
        let result = server_rekey(&server_session, &opened.payload, &leaf, now()).unwrap();
        let response_frame = server_session
            .seal(Kind::Response, "session.rekey", 1, &result.response)
            .unwrap();
        let response = client_session.open(&response_frame).unwrap();
        rekey
            .finish(&mut client_session, &response.payload)
            .unwrap();
        server_session.rotate(result.send_key, result.recv_key, now());

        assert_eq!(client_session.epoch(), 1);
        assert_eq!(server_session.epoch(), 1);
        let ping = client_session
            .seal(Kind::Request, "ping", 2, &Value::Null)
            .unwrap();
        server_session.open(&ping).unwrap();
    }

    #[test]
    fn stale_rekey_is_rejected() {
        let issuer = ServerKeys::generate().unwrap();
        let leaf = ServerKeys::generate().unwrap();
        let certificate = Certificate::issue(
            &leaf,
            &issuer,
            "server-1",
            now() - 60_000,
            now() + 3_600_000,
        )
        .unwrap()
        .marshal()
        .unwrap();
        let (mut client, request) =
            ClientHandshake::new(issuer.public(), now(), "server-1").unwrap();
        let (response, server_session) = server_handshake(
            &request,
            ServerHandshakeOptions {
                keys: &leaf,
                certificate: &certificate,
                replay_seen: None,
                now_ms: now(),
                policy: SessionPolicy::default(),
            },
        )
        .unwrap();
        let mut client_session = client.finish(&response).unwrap();
        client_session.set_clock(now);
        let (_, payload) = RekeyClient::new(&client_session, leaf.public(), now()).unwrap();
        let mut map = payload.as_map().unwrap().clone();
        map.insert("epoch".into(), Value::Int(99));
        let stale = Value::Map(map);
        assert!(server_rekey(&server_session, &stale, &leaf, now()).is_err());
    }
}
