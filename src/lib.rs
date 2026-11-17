//! NMT v2 protocol core.
//!
//! This crate ports the protocol layer from `nmt-protocol-go`:
//! NMTB, certificates, hybrid handshake, AEAD frames and rekey.
//! It intentionally does not include HTTP/WebSocket server or client code.

pub mod certificate;
pub mod error;
pub mod handshake;
pub mod keys;
pub mod nmtb;
pub mod rekey;
pub mod session;
mod util;

pub use certificate::Certificate;
pub use error::Error;
pub use handshake::{
    ClientHandshake, HANDSHAKE_TRANSCRIPT_DOMAIN, ReplaySeen, ServerHandshakeOptions, SessionKeys,
    VERSION, server_handshake,
};
pub use keys::{ServerKeys, ServerPublicKeys, generate_server_keys, parse_server_keys};
pub use nmtb::Value;
pub use rekey::{RekeyClient, RekeyResult, server_rekey};
pub use session::{
    DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_REKEY_INTERVAL_MS, DEFAULT_SESSION_TTL_MS, Frame, Kind,
    Session, SessionPolicy,
};
