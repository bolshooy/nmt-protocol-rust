//! In-band rekey: fresh X25519 + ML-KEM-1024, new keys and epoch.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use ml_kem::{Decapsulate, Kem, KeyExport, MlKem1024};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::error::Error;
use crate::handshake::VERSION;
use crate::keys::{ServerPublicKeys, random_bytes, verify_server_signatures};
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
