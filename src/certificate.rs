//! NMT server certificates.
//!
//! A certificate binds leaf signing keys to a long-lived issuer key. It is
//! deliberately not X.509: the wire format is canonical NMTB.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::keys::{ServerPublicKeys, parse_server_public_keys, verify_server_signatures};
use crate::nmtb::{self, Value};
use crate::util::{bytes_field, int_field, signing_input, string_field};

pub const CERTIFICATE_VERSION: i64 = 1;
pub const CERTIFICATE_DOMAIN: &[u8] = b"NMT/v2/certificate\0";
pub const MAX_CERTIFICATE_SIZE: usize = 64 << 10;

/// A server certificate signed by an issuer.
#[derive(Debug, Clone)]
pub struct Certificate {
    pub server_id: String,
    /// Unix milliseconds.
    pub not_before: i64,
    /// Unix milliseconds.
    pub not_after: i64,
    pub secp256k1: Vec<u8>,
    pub mldsa: Vec<u8>,
    secp256k1_signature: Vec<u8>,
    mldsa_signature: Vec<u8>,
}

impl Certificate {
    /// Encode the certificate as canonical NMTB.
    pub fn marshal(&self) -> Result<Vec<u8>, Error> {
        let mut map = BTreeMap::new();
        map.insert("version".into(), Value::Int(CERTIFICATE_VERSION));
        map.insert("server_id".into(), Value::String(self.server_id.clone()));
        map.insert("not_before".into(), Value::Int(self.not_before));
        map.insert("not_after".into(), Value::Int(self.not_after));
        map.insert("secp256k1".into(), Value::Bytes(self.secp256k1.clone()));
        map.insert("mldsa".into(), Value::Bytes(self.mldsa.clone()));
        map.insert(
            "signature_secp256k1".into(),
            Value::Bytes(self.secp256k1_signature.clone()),
        );
        map.insert(
            "signature_mldsa".into(),
            Value::Bytes(self.mldsa_signature.clone()),
        );
        Ok(nmtb::marshal(&Value::Map(map))?)
    }

    /// Decode a certificate. Signature verification is separate.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.is_empty() || data.len() > MAX_CERTIFICATE_SIZE {
            return Err(Error::Certificate("invalid size".into()));
        }
        let value =
            nmtb::unmarshal(data).map_err(|err| Error::Certificate(format!("decode: {err}")))?;
        let map = value
            .as_map()
            .ok_or_else(|| Error::Certificate("expected a map".into()))?;

        let version = int_field(map, "version")
            .ok_or_else(|| Error::Certificate("version must be an integer".into()))?;
        if version != CERTIFICATE_VERSION {
            return Err(Error::Certificate("unsupported version".into()));
        }
        let server_id = string_field(map, "server_id")
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or_else(|| Error::Certificate("server_id must be a string".into()))?;
        let not_before = int_field(map, "not_before")
            .ok_or_else(|| Error::Certificate("not_before must be an integer".into()))?;
        let not_after = int_field(map, "not_after")
            .ok_or_else(|| Error::Certificate("not_after must be an integer".into()))?;
        let secp256k1 = bytes_field(map, "secp256k1")
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or_else(|| Error::Certificate("secp256k1 must be bytes".into()))?;
        let mldsa = bytes_field(map, "mldsa")
            .filter(|value| !value.is_empty() && value.len() <= 8192)
            .ok_or_else(|| Error::Certificate("mldsa must be bytes".into()))?;
        let secp256k1_signature = bytes_field(map, "signature_secp256k1")
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or_else(|| Error::Certificate("signature_secp256k1 must be bytes".into()))?;
        let mldsa_signature = bytes_field(map, "signature_mldsa")
            .filter(|value| !value.is_empty() && value.len() <= 8192)
            .ok_or_else(|| Error::Certificate("signature_mldsa must be bytes".into()))?;

        parse_server_public_keys(&secp256k1, &mldsa)
            .map_err(|err| Error::Certificate(err.to_string()))?;

        Ok(Self {
            server_id,
            not_before,
            not_after,
            secp256k1,
            mldsa,
            secp256k1_signature,
            mldsa_signature,
        })
    }

    /// Verify the issuer signature and validity window.
    pub fn verify(&self, issuer: &ServerPublicKeys, now_ms: i64) -> Result<(), Error> {
        parse_server_public_keys(&self.secp256k1, &self.mldsa)
            .map_err(|err| Error::Certificate(err.to_string()))?;
        if now_ms < self.not_before || now_ms > self.not_after {
            return Err(Error::CertificateExpired);
        }
        let unsigned = self.unsigned_bytes()?;
        verify_server_signatures(
            issuer,
            &signing_input(CERTIFICATE_DOMAIN, &unsigned),
            &self.secp256k1_signature,
            &self.mldsa_signature,
        )
        .map_err(|err| Error::Certificate(err.to_string()))
    }

    /// Subject public keys.
    pub fn public(&self) -> ServerPublicKeys {
        ServerPublicKeys {
            secp256k1: self.secp256k1.clone(),
            mldsa: self.mldsa.clone(),
        }
    }

    /// Stable hash of the public certificate fields.
    pub fn fingerprint(&self) -> [u8; 32] {
        match self.unsigned_bytes() {
            Ok(unsigned) => Sha256::digest(unsigned).into(),
            Err(_) => [0u8; 32],
        }
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut map = BTreeMap::new();
        map.insert("version".into(), Value::Int(CERTIFICATE_VERSION));
        map.insert("server_id".into(), Value::String(self.server_id.clone()));
        map.insert("not_before".into(), Value::Int(self.not_before));
        map.insert("not_after".into(), Value::Int(self.not_after));
        map.insert("secp256k1".into(), Value::Bytes(self.secp256k1.clone()));
        map.insert("mldsa".into(), Value::Bytes(self.mldsa.clone()));
        nmtb::marshal(&Value::Map(map)).map_err(Error::from)
    }
}

/// Parse a certificate and ensure the issuer signature and validity.
pub fn verify_certificate(
    data: &[u8],
    issuer: &ServerPublicKeys,
    now_ms: i64,
) -> Result<Certificate, Error> {
    let certificate = Certificate::parse(data)?;
    certificate.verify(issuer, now_ms)?;
    Ok(certificate)
}
