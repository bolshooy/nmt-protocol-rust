//! Pinned server public keys and hybrid signature verification.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use rand_core::{OsRng, RngCore};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use sha2::{Digest, Sha256};

use crate::error::{Error, crypto};

/// Public keys pinned by clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPublicKeys {
    pub secp256k1: Vec<u8>,
    pub mldsa: Vec<u8>,
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
    if !mldsa_public.verify(message, mldsa_signature, &[]) {
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
