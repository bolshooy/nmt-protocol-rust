use crate::nmtb;

/// Protocol error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("nmtb: {0}")]
    Nmtb(#[from] nmtb::Error),

    #[error("invalid NMT certificate: {0}")]
    Certificate(String),

    #[error("NMT certificate is not valid at this time")]
    CertificateExpired,

    #[error("invalid handshake: {0}")]
    Handshake(String),

    #[error("replayed handshake")]
    HandshakeReplay,

    #[error("handshake timestamp outside allowed window")]
    ClockSkew,

    #[error("invalid NMT frame: {0}")]
    Frame(String),

    #[error("replayed NMT frame")]
    FrameReplay,

    #[error("session expired")]
    SessionExpired,

    #[error("not authenticated")]
    NotAuthenticated,

    #[error("API error {code}: {message}")]
    Api { code: String, message: String },

    #[error("HTTP transport: {0}")]
    Http(String),

    #[error("WebSocket transport: {0}")]
    WebSocket(String),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("{0}")]
    Message(String),
}

pub(crate) fn crypto(value: impl Into<String>) -> Error {
    Error::Crypto(value.into())
}
