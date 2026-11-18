//! NMT v2 protocol client.
//!
//! This crate ports the client side of `nmt-protocol-go`: NMTB, certificate
//! verification, hybrid handshake, AEAD frames, rekey and HTTP/WebSocket
//! transport. The server implementation is intentionally not part of this
//! crate.

pub mod certificate;
pub mod client;
pub mod error;
pub mod handshake;
pub mod keys;
pub mod nmtb;
pub mod rekey;
pub mod session;
mod util;

pub use certificate::Certificate;
pub use client::{Client, EventPoll, EventStream};
pub use error::Error;
pub use handshake::{ClientHandshake, HANDSHAKE_TRANSCRIPT_DOMAIN, SessionKeys, VERSION};
pub use keys::{ServerPublicKeys, parse_server_public_keys};
pub use nmtb::Value;
pub use rekey::RekeyClient;
pub use session::{
    DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_REKEY_INTERVAL_MS, DEFAULT_REKEY_MESSAGES,
    DEFAULT_SESSION_TTL_MS, Frame, Kind, Session, SessionPolicy,
};
