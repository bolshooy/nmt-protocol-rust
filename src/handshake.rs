//! Hybrid X25519 + ML-KEM-1024 handshake with certificate-based server
//! authentication.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use ml_kem::{Decapsulate, Kem, KeyExport, MlKem1024};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::certificate::{MAX_CERTIFICATE_SIZE, verify_certificate};
use crate::error::Error;
use crate::keys::{ServerPublicKeys, parse_server_public_keys, verify_server_signatures};
use crate::nmtb::{self, Value};
use crate::session::{Session, SessionPolicy};
use crate::util::check_timestamp;

pub const VERSION: i64 = 2;

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
        let rekey_messages = map_int(message, "rekey_messages")?;
        let policy = SessionPolicy {
            ttl_ms,
            idle_timeout_ms: idle_ms,
            rekey_interval_ms: rekey_ms,
            rekey_messages,
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
        server_map.insert("rekey_messages".into(), Value::Int(rekey_messages));
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
