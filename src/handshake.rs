//! Hybrid X25519 + ML-KEM-1024 handshake with certificate-based server
//! authentication.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::certificate::{MAX_CERTIFICATE_SIZE, verify_certificate};
use crate::error::Error;
use crate::keys::{
    ServerKeys, ServerPublicKeys, parse_server_public_keys, verify_server_signatures,
};
use crate::nmtb::{self, Value};
use crate::session::{Session, SessionPolicy};
use crate::util::check_timestamp;

pub const VERSION: i64 = 2;

/// Callback used to reject replayed ClientHello nonces.
pub type ReplaySeen<'a> = &'a mut dyn FnMut(&[u8]) -> bool;

/// `(c2s, s2c, session_id, handle)`.
pub type SessionKeys = ([u8; 32], [u8; 32], [u8; 16], [u8; 16]);
pub const HANDSHAKE_TRANSCRIPT_DOMAIN: &[u8] = b"NMT/v2/handshake\0";

/// Client-side ephemeral state between ClientHello and ServerHello.
pub struct ClientHandshake {
    unsigned: Vec<u8>,
    x_private: StaticSecret,
    mlkem_private: <MlKem1024 as Kem>::DecapsulationKey,
    client_nonce: Vec<u8>,
    issuer: ServerPublicKeys,
    server_keys: Option<ServerPublicKeys>,
    expected_server_id: String,
    now_ms: i64,
}

impl ClientHandshake {
    /// Build a signed ClientHello. The client is anonymous; only the server
    /// proves its identity with a certificate.
    pub fn new(
        issuer: ServerPublicKeys,
        now_ms: i64,
        expected_server_id: impl Into<String>,
    ) -> Result<(Self, Vec<u8>), Error> {
        parse_server_public_keys(&issuer.secp256k1, &issuer.mldsa)?;
        let x_private = StaticSecret::from(random_array::<32>()?);
        let x_public = X25519PublicKey::from(&x_private);
        let (mlkem_private, mlkem_public) = MlKem1024::generate_keypair();
        let client_nonce = crate::keys::random_bytes(32)?;

        let mut map = BTreeMap::new();
        map.insert("version".into(), Value::Int(VERSION));
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
        let unsigned = nmtb::marshal(&Value::Map(map))?;

        Ok((
            Self {
                unsigned: unsigned.clone(),
                x_private,
                mlkem_private,
                client_nonce,
                issuer,
                server_keys: None,
                expected_server_id: expected_server_id.into(),
                now_ms,
            },
            unsigned,
        ))
    }

    /// Leaf public keys from the verified certificate, available after
    /// `finish` and used for rekey verification.
    pub fn server_keys(&self) -> Option<&ServerPublicKeys> {
        self.server_keys.as_ref()
    }

    /// Verify ServerHello and derive the client session.
    pub fn finish(&mut self, response: &[u8]) -> Result<Session, Error> {
        let value =
            nmtb::unmarshal(response).map_err(|err| Error::Handshake(format!("decode: {err}")))?;
        let message = value
            .as_map()
            .ok_or_else(|| Error::Handshake("expected a map".into()))?;
        if let Some(ok) = message.get("ok").and_then(Value::as_bool) {
            if !ok {
                return Err(handshake_error(message));
            }
        }

        let version = map_int(message, "version")?;
        if version != VERSION {
            return Err(Error::Handshake("unsupported version".into()));
        }
        let server_nonce = map_bytes(message, "server_nonce", 32, 32)?;
        let server_x25519 = map_bytes(message, "server_x25519", 32, 32)?;
        let mlkem_ciphertext = map_bytes(message, "mlkem_ciphertext", 1, 4096)?;
        let timestamp = map_int(message, "timestamp")?;
        check_timestamp(self.now_ms, timestamp)?;
        let certificate_bytes = map_bytes(message, "certificate", 1, MAX_CERTIFICATE_SIZE)?;
        let certificate = verify_certificate(&certificate_bytes, &self.issuer, self.now_ms)?;
        if !self.expected_server_id.is_empty() && certificate.server_id != self.expected_server_id {
            return Err(Error::Certificate(format!(
                "unexpected server id {:?}",
                certificate.server_id
            )));
        }
        self.server_keys = Some(certificate.public());

        let secp_signature = map_bytes(message, "signature_secp256k1", 1, 128)?;
        let mldsa_signature = map_bytes(message, "signature_mldsa", 1, 8192)?;
        let session_id_bytes = map_bytes(message, "session_id", 16, 16)?;
        let ttl_ms = map_int(message, "ttl_ms")?;
        let idle_ms = map_int(message, "idle_ms")?;
        let rekey_ms = map_int(message, "rekey_ms")?;
        let policy = SessionPolicy {
            ttl_ms,
            idle_timeout_ms: idle_ms,
            rekey_interval_ms: rekey_ms,
        }
        .normalized();

        let mut server_map = BTreeMap::new();
        server_map.insert("version".into(), Value::Int(version));
        server_map.insert("server_nonce".into(), Value::Bytes(server_nonce.clone()));
        server_map.insert("server_x25519".into(), Value::Bytes(server_x25519.clone()));
        server_map.insert(
            "mlkem_ciphertext".into(),
            Value::Bytes(mlkem_ciphertext.clone()),
        );
        server_map.insert("timestamp".into(), Value::Int(timestamp));
        server_map.insert(
            "certificate".into(),
            Value::Bytes(certificate_bytes.clone()),
        );
        server_map.insert("ttl_ms".into(), Value::Int(ttl_ms));
        server_map.insert("idle_ms".into(), Value::Int(idle_ms));
        server_map.insert("rekey_ms".into(), Value::Int(rekey_ms));
        let server_unsigned = nmtb::marshal(&Value::Map(server_map))?;
        let transcript = handshake_transcript(
            &self.unsigned,
            &server_unsigned,
            &self.client_nonce,
            &server_nonce,
        );

        let server_keys = self.server_keys.as_ref().expect("set immediately above");
        verify_server_signatures(server_keys, &transcript, &secp_signature, &mldsa_signature)?;

        let peer_public = X25519PublicKey::from(array_32(&server_x25519)?);
        let x_shared = self.x_private.diffie_hellman(&peer_public);
        let mlkem_shared = self
            .mlkem_private
            .decapsulate_slice(&mlkem_ciphertext)
            .map_err(|_| Error::Handshake("ml-kem decapsulation failed".into()))?;
        let (c2s, s2c, session_id, handle) =
            derive_session_keys(x_shared.as_bytes(), mlkem_shared.as_slice(), &transcript)?;
        if session_id.as_slice() != session_id_bytes.as_slice() {
            return Err(Error::Handshake("session id mismatch".into()));
        }

        Ok(Session::new(
            session_id,
            handle,
            c2s,
            s2c,
            self.now_ms,
            policy,
        ))
    }
}

/// Server-side handshake options.
pub struct ServerHandshakeOptions<'a> {
    pub keys: &'a ServerKeys,
    pub certificate: &'a [u8],
    pub replay_seen: Option<ReplaySeen<'a>>,
    pub now_ms: i64,
    pub policy: SessionPolicy,
}

/// Process ClientHello and return ServerHello plus the server session.
pub fn server_handshake(
    request: &[u8],
    mut options: ServerHandshakeOptions<'_>,
) -> Result<(Vec<u8>, Session), Error> {
    if options.certificate.is_empty() {
        return Err(Error::Message("server certificate is required".into()));
    }
    let value =
        nmtb::unmarshal(request).map_err(|err| Error::Handshake(format!("decode: {err}")))?;
    let message = value
        .as_map()
        .ok_or_else(|| Error::Handshake("expected a map".into()))?;
    if let Some(ok) = message.get("ok").and_then(Value::as_bool) {
        if !ok {
            return Err(handshake_error(message));
        }
    }

    let version = map_int(message, "version")?;
    if version != VERSION {
        return Err(Error::Handshake("unsupported version".into()));
    }
    let client_nonce = map_bytes(message, "client_nonce", 32, 32)?;
    let client_x25519 = map_bytes(message, "client_x25519", 32, 32)?;
    let client_mlkem = map_bytes(message, "client_mlkem", 1, 4096)?;
    let timestamp = map_int(message, "timestamp")?;
    check_timestamp(options.now_ms, timestamp)?;
    if let Some(replay_seen) = options.replay_seen.as_mut() {
        if replay_seen(&client_nonce) {
            return Err(Error::HandshakeReplay);
        }
    }

    let mut client_map = BTreeMap::new();
    client_map.insert("version".into(), Value::Int(version));
    client_map.insert("client_nonce".into(), Value::Bytes(client_nonce.clone()));
    client_map.insert("client_x25519".into(), Value::Bytes(client_x25519.clone()));
    client_map.insert("client_mlkem".into(), Value::Bytes(client_mlkem.clone()));
    client_map.insert("timestamp".into(), Value::Int(timestamp));
    let client_unsigned = nmtb::marshal(&Value::Map(client_map))?;
    if client_unsigned != request {
        return Err(Error::Handshake("non-canonical ClientHello".into()));
    }

    let x_private = StaticSecret::from(random_array::<32>()?);
    let x_public = X25519PublicKey::from(&x_private);
    let client_public = X25519PublicKey::from(array_32(&client_x25519)?);
    let x_shared = x_private.diffie_hellman(&client_public);

    let encapsulation_key =
        <<MlKem1024 as Kem>::EncapsulationKey as TryKeyInit>::new_from_slice(&client_mlkem)
            .map_err(|_| Error::Handshake("client ml-kem key is invalid".into()))?;
    let (mlkem_ciphertext, mlkem_shared) = encapsulation_key.encapsulate();

    let server_nonce = crate::keys::random_bytes(32)?;
    let policy = options.policy.normalized();
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
    server_map.insert("timestamp".into(), Value::Int(options.now_ms));
    server_map.insert(
        "certificate".into(),
        Value::Bytes(options.certificate.to_vec()),
    );
    server_map.insert("ttl_ms".into(), Value::Int(policy.ttl_ms));
    server_map.insert("idle_ms".into(), Value::Int(policy.idle_timeout_ms));
    server_map.insert("rekey_ms".into(), Value::Int(policy.rekey_interval_ms));
    let server_unsigned = nmtb::marshal(&Value::Map(server_map))?;
    let transcript = handshake_transcript(
        &client_unsigned,
        &server_unsigned,
        &client_nonce,
        &server_nonce,
    );
    let (secp_signature, mldsa_signature) = options.keys.sign(&transcript)?;
    let (c2s, s2c, session_id, handle) =
        derive_session_keys(x_shared.as_bytes(), mlkem_shared.as_slice(), &transcript)?;

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
    response.insert("timestamp".into(), Value::Int(options.now_ms));
    response.insert(
        "certificate".into(),
        Value::Bytes(options.certificate.to_vec()),
    );
    response.insert("ttl_ms".into(), Value::Int(policy.ttl_ms));
    response.insert("idle_ms".into(), Value::Int(policy.idle_timeout_ms));
    response.insert("rekey_ms".into(), Value::Int(policy.rekey_interval_ms));
    response.insert("signature_secp256k1".into(), Value::Bytes(secp_signature));
    response.insert("signature_mldsa".into(), Value::Bytes(mldsa_signature));
    response.insert("session_id".into(), Value::Bytes(session_id.to_vec()));
    let response = nmtb::marshal(&Value::Map(response))?;

    let session = Session::new(session_id, handle, s2c, c2s, options.now_ms, policy);
    Ok((response, session))
}

fn handshake_transcript(
    client_unsigned: &[u8],
    server_unsigned: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        HANDSHAKE_TRANSCRIPT_DOMAIN.len()
            + client_unsigned.len()
            + server_unsigned.len()
            + client_nonce.len()
            + server_nonce.len(),
    );
    input.extend_from_slice(HANDSHAKE_TRANSCRIPT_DOMAIN);
    input.extend_from_slice(client_unsigned);
    input.extend_from_slice(server_unsigned);
    input.extend_from_slice(client_nonce);
    input.extend_from_slice(server_nonce);
    Sha256::digest(input).into()
}

fn derive_session_keys(
    x_shared: &[u8],
    mlkem_shared: &[u8],
    transcript: &[u8],
) -> Result<SessionKeys, Error> {
    let mut ikm = Vec::with_capacity(x_shared.len() + mlkem_shared.len());
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(mlkem_shared);
    let hkdf = Hkdf::<Sha256>::new(Some(transcript), &ikm);
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    let mut session = [0u8; 32];
    let mut handle = [0u8; 32];
    hkdf.expand(b"NMT/v2/c2s", &mut c2s)
        .map_err(|_| Error::Crypto("hkdf c2s".into()))?;
    hkdf.expand(b"NMT/v2/s2c", &mut s2c)
        .map_err(|_| Error::Crypto("hkdf s2c".into()))?;
    hkdf.expand(b"NMT/v2/session", &mut session)
        .map_err(|_| Error::Crypto("hkdf session".into()))?;
    hkdf.expand(b"NMT/v2/handle", &mut handle)
        .map_err(|_| Error::Crypto("hkdf handle".into()))?;
    let mut session_id = [0u8; 16];
    let mut routing_handle = [0u8; 16];
    session_id.copy_from_slice(&session[..16]);
    routing_handle.copy_from_slice(&handle[..16]);
    Ok((c2s, s2c, session_id, routing_handle))
}

fn handshake_error(map: &BTreeMap<String, Value>) -> Error {
    let message = map
        .get("error")
        .and_then(Value::as_map)
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("handshake failed");
    Error::Handshake(message.to_owned())
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
    let bytes = crate::keys::random_bytes(N)?;
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
    use crate::keys::ServerKeys;

    fn now() -> i64 {
        1_700_000_000_000
    }

    fn fixture() -> (ServerKeys, ServerKeys, Vec<u8>) {
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
        (issuer, leaf, certificate)
    }

    #[test]
    fn handshake_and_frames() {
        let (issuer, leaf, certificate) = fixture();
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
        assert_eq!(client_session.id, server_session.id);
        assert_eq!(client_session.handle, server_session.handle);
        assert_ne!(client_session.handle, client_session.id);
        assert_eq!(client.server_keys().unwrap(), &leaf.public());

        let payload = Value::Map(BTreeMap::new());
        let frame = client_session
            .seal(crate::session::Kind::Request, "ping", 1, &payload)
            .unwrap();
        let decoded = server_session.open(&frame).unwrap();
        assert_eq!(decoded.method, "ping");
        assert_eq!(decoded.request_id, 1);
        assert!(matches!(
            server_session.open(&frame),
            Err(Error::FrameReplay)
        ));
    }

    #[test]
    fn rejects_wrong_issuer_and_server_id() {
        let (issuer, leaf, certificate) = fixture();
        let (mut client, request) = ClientHandshake::new(issuer.public(), now(), "other").unwrap();
        let (response, _) = server_handshake(
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
        assert!(client.finish(&response).is_err());

        let other_issuer = ServerKeys::generate().unwrap();
        let (mut client, request) =
            ClientHandshake::new(other_issuer.public(), now(), "server-1").unwrap();
        let (response, _) = server_handshake(
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
        assert!(client.finish(&response).is_err());
    }

    #[test]
    fn rejects_replay_and_clock_skew() {
        let (issuer, leaf, certificate) = fixture();
        let mut seen = false;
        let (mut client, request) =
            ClientHandshake::new(issuer.public(), now(), "server-1").unwrap();
        let mut replay = |_: &[u8]| {
            if seen {
                true
            } else {
                seen = true;
                false
            }
        };
        let (response, _) = server_handshake(
            &request,
            ServerHandshakeOptions {
                keys: &leaf,
                certificate: &certificate,
                replay_seen: Some(&mut replay),
                now_ms: now(),
                policy: SessionPolicy::default(),
            },
        )
        .unwrap();
        client.finish(&response).unwrap();
        assert!(matches!(
            server_handshake(
                &request,
                ServerHandshakeOptions {
                    keys: &leaf,
                    certificate: &certificate,
                    replay_seen: Some(&mut replay),
                    now_ms: now(),
                    policy: SessionPolicy::default(),
                },
            ),
            Err(Error::HandshakeReplay)
        ));

        let (_, request) =
            ClientHandshake::new(issuer.public(), now() - 3_600_000, "server-1").unwrap();
        assert!(matches!(
            server_handshake(
                &request,
                ServerHandshakeOptions {
                    keys: &leaf,
                    certificate: &certificate,
                    replay_seen: None,
                    now_ms: now(),
                    policy: SessionPolicy::default(),
                },
            ),
            Err(Error::ClockSkew)
        ));
    }

    #[test]
    fn rejects_tampered_server_hello() {
        let (issuer, leaf, certificate) = fixture();
        let (mut client, request) =
            ClientHandshake::new(issuer.public(), now(), "server-1").unwrap();
        let (response, _) = server_handshake(
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
        let mut tampered = response;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(client.finish(&tampered).is_err());
    }
}
