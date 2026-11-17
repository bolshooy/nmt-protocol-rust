//! Long-term server keys and hybrid signatures.

use std::fmt;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use rand_core::{OsRng, RngCore};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use sha2::{Digest, Sha256};

use crate::error::{Error, crypto};

/// Long-term server authentication keys.
pub struct ServerKeys {
    secp256k1: SecretKey,
    mldsa: ml_dsa_65::PrivateKey,
}

impl fmt::Debug for ServerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerKeys").finish_non_exhaustive()
    }
}

/// Public keys pinned by clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPublicKeys {
    pub secp256k1: Vec<u8>,
    pub mldsa: Vec<u8>,
}

impl ServerKeys {
    /// Generate secp256k1 and ML-DSA-65 keys.
    pub fn generate() -> Result<Self, Error> {
        let mut secp_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secp_bytes);
        let secp256k1 = SecretKey::from_byte_array(secp_bytes)
            .map_err(|err| crypto(format!("secp256k1 key: {err}")))?;
        let (_, mldsa) =
            ml_dsa_65::try_keygen().map_err(|err| crypto(format!("ml-dsa key: {err}")))?;
        Ok(Self { secp256k1, mldsa })
    }

    /// Public keys suitable for pinning.
    pub fn public(&self) -> ServerPublicKeys {
        let secp256k1 = PublicKey::from_secret_key(&Secp256k1::new(), &self.secp256k1)
            .serialize()
            .to_vec();
        let mldsa = self.mldsa.get_public_key().into_bytes().to_vec();
        ServerPublicKeys { secp256k1, mldsa }
    }

    /// Serialize private key material for configuration storage.
    pub fn private_bytes(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.secp256k1.secret_bytes().to_vec(),
            self.mldsa.clone().into_bytes().to_vec(),
        )
    }

    /// Restore private keys from serialized material.
    pub fn from_private_bytes(secp256k1: &[u8], mldsa: &[u8]) -> Result<Self, Error> {
        if secp256k1.len() != 32 {
            return Err(crypto("invalid secp256k1 private key length"));
        }
        let secp256k1_array: [u8; 32] = secp256k1
            .try_into()
            .map_err(|_| crypto("invalid secp256k1 private key length"))?;
        let secp256k1 = SecretKey::from_byte_array(secp256k1_array)
            .map_err(|err| crypto(format!("invalid secp256k1 private key: {err}")))?;
        let mldsa_bytes: [u8; ml_dsa_65::SK_LEN] = mldsa
            .try_into()
            .map_err(|_| crypto("invalid ml-dsa private key length"))?;
        let mldsa = ml_dsa_65::PrivateKey::try_from_bytes(mldsa_bytes)
            .map_err(|err| crypto(format!("invalid ml-dsa private key: {err}")))?;
        Ok(Self { secp256k1, mldsa })
    }

    /// Sign a message with both private keys.
    pub fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let secp = Secp256k1::new();
        let digest: [u8; 32] = Sha256::digest(message).into();
        let secp_message = Message::from_digest(digest);
        let signature = secp.sign_ecdsa(secp_message, &self.secp256k1);
        let mldsa = self
            .mldsa
            .try_sign(message, &[])
            .map_err(|err| crypto(format!("ml-dsa sign: {err}")))?;
        Ok((signature.serialize_der().to_vec(), mldsa.to_vec()))
    }
}

/// Generate a fresh server key set.
pub fn generate_server_keys() -> Result<ServerKeys, Error> {
    ServerKeys::generate()
}

/// Restore private keys from serialized material.
pub fn parse_server_keys(secp256k1: &[u8], mldsa: &[u8]) -> Result<ServerKeys, Error> {
    ServerKeys::from_private_bytes(secp256k1, mldsa)
}

/// Parse pinned public key bytes.
pub fn parse_server_public_keys(secp256k1: &[u8], mldsa: &[u8]) -> Result<ServerPublicKeys, Error> {
    PublicKey::from_slice(secp256k1)
        .map_err(|err| crypto(format!("secp256k1 public key: {err}")))?;
    let mldsa_bytes: [u8; ml_dsa_65::PK_LEN] = mldsa
        .try_into()
        .map_err(|_| crypto("invalid ml-dsa public key length"))?;
    ml_dsa_65::PublicKey::try_from_bytes(mldsa_bytes)
        .map_err(|err| crypto(format!("ml-dsa public key: {err}")))?;
    Ok(ServerPublicKeys {
        secp256k1: secp256k1.to_vec(),
        mldsa: mldsa.to_vec(),
    })
}

/// Verify both signatures over a message.
pub fn verify_server_signatures(
    public: &ServerPublicKeys,
    message: &[u8],
    secp256k1_signature: &[u8],
    mldsa_signature: &[u8],
) -> Result<(), Error> {
    let public_key = PublicKey::from_slice(&public.secp256k1)
        .map_err(|err| crypto(format!("secp256k1 public key: {err}")))?;
    let signature = Signature::from_der(secp256k1_signature)
        .map_err(|err| crypto(format!("secp256k1 signature: {err}")))?;
    let digest: [u8; 32] = Sha256::digest(message).into();
    let secp_message = Message::from_digest(digest);
    Secp256k1::new()
        .verify_ecdsa(secp_message, &signature, &public_key)
        .map_err(|_| crypto("secp256k1 signature verification failed"))?;

    let mldsa_bytes: [u8; ml_dsa_65::PK_LEN] = public
        .mldsa
        .as_slice()
        .try_into()
        .map_err(|_| crypto("invalid ml-dsa public key length"))?;
    let mldsa_public = ml_dsa_65::PublicKey::try_from_bytes(mldsa_bytes)
        .map_err(|err| crypto(format!("ml-dsa public key: {err}")))?;
    let mldsa_signature: &[u8; ml_dsa_65::SIG_LEN] = mldsa_signature
        .try_into()
        .map_err(|_| crypto("invalid ml-dsa signature length"))?;
    if !mldsa_public.verify(message.as_ref(), mldsa_signature, &[]) {
        return Err(crypto("ml-dsa signature verification failed"));
    }
    Ok(())
}

/// Return cryptographically secure random bytes.
pub fn random_bytes(length: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0u8; length];
    OsRng.fill_bytes(&mut value);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let keys = ServerKeys::generate().unwrap();
        let public = keys.public();
        let parsed = parse_server_public_keys(&public.secp256k1, &public.mldsa).unwrap();
        let (secp, mldsa) = keys.sign(b"hello").unwrap();
        verify_server_signatures(&parsed, b"hello", &secp, &mldsa).unwrap();
        assert!(verify_server_signatures(&parsed, b"other", &secp, &mldsa).is_err());
    }

    #[test]
    fn private_key_round_trip() {
        let keys = ServerKeys::generate().unwrap();
        let (secp, mldsa) = keys.private_bytes();
        let restored = ServerKeys::from_private_bytes(&secp, &mldsa).unwrap();
        assert_eq!(keys.public(), restored.public());
    }
}
