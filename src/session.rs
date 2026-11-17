//! NMT v2 sessions, encrypted frames, replay protection and rekey state.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::Error;
use crate::nmtb::{self, Value};
use crate::util::check_timestamp;

pub const FRAME_MAGIC: &[u8; 4] = b"NMT2";
pub const FRAME_VERSION: u8 = 2;
pub const INNER_VERSION: u8 = 1;
pub const MAX_FRAME_SIZE: usize = 1 << 20;
pub const MAX_METHOD_LEN: usize = 128;
pub const REPLAY_WINDOW_MS: i64 = 10 * 60 * 1000;
pub const TAG_SIZE: usize = 16;
pub const OUTER_HEADER_SIZE: usize = 4 + 1 + 16 + 12;
pub const INNER_FIXED: usize = 1 + 1 + 1 + 1 + 8 + 8 + 2 + 4;
pub const WS_PROOF_DOMAIN: &[u8] = b"NMT/v2/ws\0";

pub const DEFAULT_SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;
pub const DEFAULT_IDLE_TIMEOUT_MS: i64 = 30 * 60 * 1000;
pub const DEFAULT_REKEY_INTERVAL_MS: i64 = 60 * 60 * 1000;

/// Session lifetime and key rotation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Absolute lifetime in milliseconds. Rekey does not extend it.
    pub ttl_ms: i64,
    /// Idle timeout in milliseconds. 0 is normalized to the default.
    pub idle_timeout_ms: i64,
    /// Rekey interval in milliseconds.
    pub rekey_interval_ms: i64,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            ttl_ms: DEFAULT_SESSION_TTL_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            rekey_interval_ms: DEFAULT_REKEY_INTERVAL_MS,
        }
    }
}

impl SessionPolicy {
    pub fn normalized(self) -> Self {
        let defaults = Self::default();
        let mut value = self;
        if value.ttl_ms <= 0 {
            value.ttl_ms = defaults.ttl_ms;
        }
        if value.idle_timeout_ms < 0 {
            value.idle_timeout_ms = 0;
        } else if value.idle_timeout_ms == 0 {
            value.idle_timeout_ms = defaults.idle_timeout_ms;
        }
        if value.rekey_interval_ms <= 0 {
            value.rekey_interval_ms = defaults.rekey_interval_ms;
        }
        value
    }
}

/// Logical frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Request = 1,
    Response = 2,
    Event = 3,
    Error = 4,
}

impl Kind {
    pub fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Request,
            2 => Self::Response,
            3 => Self::Event,
            4 => Self::Error,
            _ => return None,
        })
    }
}

/// Decoded NMT frame.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub kind: Kind,
    pub method: String,
    pub request_id: u64,
    pub handle: [u8; 16],
    pub timestamp_ms: i64,
    pub payload: Value,
}

/// A live NMT session.
pub struct Session {
    pub id: [u8; 16],
    pub handle: [u8; 16],
    pub expires_ms: i64,

    policy: SessionPolicy,

    send_key: [u8; 32],
    recv_key: [u8; 32],
    prev_recv_key: Option<[u8; 32]>,
    prev_recv_till_ms: i64,

    last_activity_ms: i64,
    last_rekey_ms: i64,
    epoch: u64,
    seen: HashMap<[u8; 12], i64>,

    now: Box<dyn Fn() -> i64 + Send + Sync>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id_hex())
            .field("handle", &self.handle_hex())
            .field("expires_ms", &self.expires_ms)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Build a session. The server passes `send = s2c`, `recv = c2s`; the
    /// client passes the reverse.
    pub fn new(
        id: [u8; 16],
        handle: [u8; 16],
        send_key: [u8; 32],
        recv_key: [u8; 32],
        now_ms: i64,
        policy: SessionPolicy,
    ) -> Self {
        let policy = policy.normalized();
        Self {
            id,
            handle,
            expires_ms: now_ms.saturating_add(policy.ttl_ms),
            policy,
            send_key,
            recv_key,
            prev_recv_key: None,
            prev_recv_till_ms: 0,
            last_activity_ms: now_ms,
            last_rekey_ms: now_ms,
            epoch: 0,
            seen: HashMap::new(),
            now: Box::new(current_time_ms),
        }
    }

    /// Override the clock. Useful for deterministic tests.
    pub fn set_clock(&mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) {
        self.now = Box::new(clock);
    }

    pub fn policy(&self) -> SessionPolicy {
        self.policy
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn expired(&self, now_ms: i64) -> bool {
        if now_ms > self.expires_ms {
            return true;
        }
        if self.policy.idle_timeout_ms > 0
            && now_ms.saturating_sub(self.last_activity_ms) > self.policy.idle_timeout_ms
        {
            return true;
        }
        false
    }

    pub fn needs_rekey(&self, now_ms: i64) -> bool {
        self.policy.rekey_interval_ms > 0
            && now_ms.saturating_sub(self.last_rekey_ms) >= self.policy.rekey_interval_ms
    }

    pub fn touch(&mut self, now_ms: i64) {
        if now_ms > self.last_activity_ms {
            self.last_activity_ms = now_ms;
        }
    }

    /// Install new keys and keep the previous receive key for a short overlap.
    /// The absolute TTL and the replay cache are preserved.
    pub fn rotate(&mut self, send_key: [u8; 32], recv_key: [u8; 32], now_ms: i64) {
        self.prev_recv_key = Some(self.recv_key);
        self.prev_recv_till_ms = now_ms.saturating_add(30_000);
        self.send_key = send_key;
        self.recv_key = recv_key;
        self.epoch = self.epoch.wrapping_add(1);
        self.last_rekey_ms = now_ms;
        self.touch(now_ms);
    }

    pub fn handle_hex(&self) -> String {
        hex::encode(self.handle)
    }

    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// Return a proof of possession of the client-to-server key for a
    /// WebSocket upgrade.
    pub fn auth_proof(&self, now_ms: i64) -> String {
        let mac = upgrade_proof(&self.send_key, &self.handle, now_ms);
        format!("{now_ms}:{}", hex::encode(mac))
    }

    /// Verify a WebSocket upgrade proof with the receive key, accepting the
    /// previous key during the rekey overlap.
    pub fn verify_auth_proof(&self, proof: &str, now_ms: i64) -> Result<(), Error> {
        let (timestamp, mac) = proof
            .split_once(':')
            .ok_or_else(|| Error::Message("invalid upgrade proof".into()))?;
        let timestamp: i64 = timestamp
            .parse()
            .map_err(|_| Error::Message("invalid upgrade proof timestamp".into()))?;
        if (now_ms - timestamp).abs() > crate::util::MAX_CLOCK_SKEW_MS {
            return Err(Error::Message(
                "upgrade proof timestamp outside allowed window".into(),
            ));
        }
        let mac = hex::decode(mac)
            .map_err(|_| Error::Message("invalid upgrade proof encoding".into()))?;
        let expected = upgrade_proof(&self.recv_key, &self.handle, timestamp);
        if bool::from(mac.as_slice().ct_eq(expected.as_slice())) {
            return Ok(());
        }
        if let Some(previous) = &self.prev_recv_key {
            if now_ms < self.prev_recv_till_ms {
                let expected = upgrade_proof(previous, &self.handle, timestamp);
                if bool::from(mac.as_slice().ct_eq(expected.as_slice())) {
                    return Ok(());
                }
            }
        }
        Err(Error::Message("invalid upgrade proof".into()))
    }

    /// Encrypt an inner header and payload into an NMT v2 frame.
    pub fn seal(
        &mut self,
        kind: Kind,
        method: &str,
        request_id: u64,
        payload: &Value,
    ) -> Result<Vec<u8>, Error> {
        let now = (self.now)();
        if self.expired(now) {
            return Err(Error::SessionExpired);
        }
        if method.is_empty() || method.len() > MAX_METHOD_LEN {
            return Err(Error::Frame("invalid method length".into()));
        }
        let encoded = nmtb::marshal(payload)?;
        if encoded.len() > MAX_FRAME_SIZE {
            return Err(Error::Frame("payload is too large".into()));
        }
        let inner_header = build_inner_header(kind, method, request_id, now, encoded.len());
        let mut inner = Vec::with_capacity(inner_header.len() + encoded.len());
        inner.extend_from_slice(&inner_header);
        inner.extend_from_slice(&encoded);

        let nonce_bytes = crate::keys::random_bytes(12)?;
        let nonce: [u8; 12] = nonce_bytes.try_into().expect("12 bytes");

        let mut outer = Vec::with_capacity(OUTER_HEADER_SIZE);
        outer.extend_from_slice(FRAME_MAGIC);
        outer.push(FRAME_VERSION);
        outer.extend_from_slice(&self.handle);
        outer.extend_from_slice(&nonce);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.send_key)
            .map_err(|_| Error::Frame("invalid send key".into()))?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &inner,
                    aad: &outer,
                },
            )
            .map_err(|_| Error::Frame("encryption failed".into()))?;
        let mut frame = Vec::with_capacity(outer.len() + sealed.len());
        frame.extend_from_slice(&outer);
        frame.extend_from_slice(&sealed);
        self.touch(now);
        Ok(frame)
    }

    /// Authenticate and decrypt an NMT v2 frame.
    pub fn open(&mut self, frame: &[u8]) -> Result<Frame, Error> {
        if frame.len() < OUTER_HEADER_SIZE + TAG_SIZE {
            return Err(Error::Frame("frame is too short".into()));
        }
        if frame.len()
            > OUTER_HEADER_SIZE + INNER_FIXED + MAX_METHOD_LEN + MAX_FRAME_SIZE + TAG_SIZE
        {
            return Err(Error::Frame("frame is too large".into()));
        }
        if &frame[0..4] != FRAME_MAGIC {
            return Err(Error::Frame("bad magic".into()));
        }
        if frame[4] != FRAME_VERSION {
            return Err(Error::Frame("unsupported version".into()));
        }
        let mut handle = [0u8; 16];
        handle.copy_from_slice(&frame[5..21]);
        if !bool::from(handle.as_slice().ct_eq(self.handle.as_slice())) {
            return Err(Error::Frame("handle mismatch".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&frame[21..33]);
        let outer = &frame[..OUTER_HEADER_SIZE];
        let ciphertext = &frame[OUTER_HEADER_SIZE..];
        let now = (self.now)();

        let inner = self
            .decrypt(&self.recv_key, &nonce, ciphertext, outer)
            .or_else(|_| {
                if let Some(previous) = &self.prev_recv_key {
                    if now < self.prev_recv_till_ms {
                        return self.decrypt(previous, &nonce, ciphertext, outer);
                    }
                }
                Err(Error::Frame("authentication failed".into()))
            })
            .map_err(|_| Error::Frame("authentication failed".into()))?;

        let decoded = parse_inner(&inner)?;
        check_timestamp(now, decoded.timestamp_ms)?;
        if self.expired(now) {
            return Err(Error::SessionExpired);
        }

        let cutoff = now.saturating_sub(REPLAY_WINDOW_MS);
        self.seen.retain(|_, seen_at| *seen_at >= cutoff);
        if self.seen.contains_key(&nonce) {
            return Err(Error::FrameReplay);
        }
        self.seen.insert(nonce, now);
        self.touch(now);

        Ok(Frame {
            kind: decoded.kind,
            method: decoded.method,
            request_id: decoded.request_id,
            handle,
            timestamp_ms: decoded.timestamp_ms,
            payload: decoded.payload,
        })
    }

    fn decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::Frame("invalid receive key".into()))?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Frame("authentication failed".into()))
    }
}

/// Return the routing handle from a frame without decrypting it.
pub fn peek_handle(frame: &[u8]) -> Result<[u8; 16], Error> {
    if frame.len() < OUTER_HEADER_SIZE + TAG_SIZE {
        return Err(Error::Frame("frame is too short".into()));
    }
    if frame.len() > OUTER_HEADER_SIZE + INNER_FIXED + MAX_METHOD_LEN + MAX_FRAME_SIZE + TAG_SIZE {
        return Err(Error::Frame("frame is too large".into()));
    }
    if &frame[0..4] != FRAME_MAGIC {
        return Err(Error::Frame("bad magic".into()));
    }
    if frame[4] != FRAME_VERSION {
        return Err(Error::Frame("unsupported version".into()));
    }
    let mut handle = [0u8; 16];
    handle.copy_from_slice(&frame[5..21]);
    Ok(handle)
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn upgrade_proof(key: &[u8; 32], handle: &[u8; 16], timestamp_ms: i64) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(WS_PROOF_DOMAIN);
    mac.update(handle);
    mac.update(&timestamp_ms.to_be_bytes());
    mac.finalize().into_bytes().into()
}

fn build_inner_header(
    kind: Kind,
    method: &str,
    request_id: u64,
    timestamp_ms: i64,
    payload_len: usize,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(INNER_FIXED + method.len());
    header.push(INNER_VERSION);
    header.push(kind as u8);
    header.push(1);
    header.push(0);
    header.extend_from_slice(&request_id.to_le_bytes());
    header.extend_from_slice(&timestamp_ms.to_le_bytes());
    header.extend_from_slice(&(method.len() as u16).to_le_bytes());
    header.extend_from_slice(&(payload_len as u32).to_le_bytes());
    header.extend_from_slice(method.as_bytes());
    header
}

struct InnerFrame {
    kind: Kind,
    method: String,
    request_id: u64,
    timestamp_ms: i64,
    payload: Value,
}

fn parse_inner(data: &[u8]) -> Result<InnerFrame, Error> {
    if data.len() < INNER_FIXED {
        return Err(Error::Frame("inner frame is too short".into()));
    }
    if data[0] != INNER_VERSION {
        return Err(Error::Frame("unsupported inner version".into()));
    }
    let kind = Kind::from_byte(data[1]).ok_or_else(|| Error::Frame("invalid kind".into()))?;
    if data[2] != 1 || data[3] != 0 {
        return Err(Error::Frame("unsupported flags".into()));
    }
    let request_id = u64::from_le_bytes(data[4..12].try_into().expect("8 bytes"));
    let timestamp_ms = i64::from_le_bytes(data[12..20].try_into().expect("8 bytes"));
    let method_len = u16::from_le_bytes(data[20..22].try_into().expect("2 bytes")) as usize;
    let payload_len = u32::from_le_bytes(data[22..26].try_into().expect("4 bytes")) as usize;
    if method_len == 0 || method_len > MAX_METHOD_LEN {
        return Err(Error::Frame("invalid method length".into()));
    }
    if payload_len > MAX_FRAME_SIZE {
        return Err(Error::Frame("invalid payload length".into()));
    }
    if data.len() != INNER_FIXED + method_len + payload_len {
        return Err(Error::Frame("invalid inner frame length".into()));
    }
    let method = std::str::from_utf8(&data[INNER_FIXED..INNER_FIXED + method_len])
        .map_err(|_| Error::Frame("invalid method encoding".into()))?
        .to_owned();
    let payload = nmtb::unmarshal(&data[INNER_FIXED + method_len..])?;
    Ok(InnerFrame {
        kind,
        method,
        request_id,
        timestamp_ms,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmtb::Value;
    use std::collections::BTreeMap;

    fn session(now_ms: i64, policy: SessionPolicy) -> Session {
        Session::new([1u8; 16], [2u8; 16], [3u8; 32], [3u8; 32], now_ms, policy)
    }

    fn payload() -> Value {
        let mut map = BTreeMap::new();
        map.insert("hello".into(), Value::String("world".into()));
        Value::Map(map)
    }

    #[test]
    fn frame_round_trip_and_replay() {
        let now = 1_700_000_000_000;
        let mut session = session(now, SessionPolicy::default());
        session.set_clock(move || now);
        let frame = session.seal(Kind::Request, "ping", 7, &payload()).unwrap();
        let decoded = session.open(&frame).unwrap();
        assert_eq!(decoded.kind, Kind::Request);
        assert_eq!(decoded.method, "ping");
        assert_eq!(decoded.request_id, 7);
        assert!(matches!(session.open(&frame), Err(Error::FrameReplay)));
    }

    #[test]
    fn frame_hides_inner_header() {
        let now = 1_700_000_000_000;
        let mut session = session(now, SessionPolicy::default());
        session.set_clock(move || now);
        let mut map = BTreeMap::new();
        map.insert("name".into(), Value::String("alice".into()));
        let frame = session
            .seal(
                Kind::Request,
                "profile",
                0x1122334455667788,
                &Value::Map(map),
            )
            .unwrap();
        assert!(!frame.windows(7).any(|window| window == b"profile"));
        assert!(!frame.windows(5).any(|window| window == b"alice"));
        assert_eq!(peek_handle(&frame).unwrap(), [2u8; 16]);
    }

    #[test]
    fn tampering_and_handle_mismatch() {
        let now = 1_700_000_000_000;
        let mut session = session(now, SessionPolicy::default());
        session.set_clock(move || now);
        let mut frame = session.seal(Kind::Request, "ping", 1, &payload()).unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        assert!(session.open(&frame).is_err());

        let mut frame = session.seal(Kind::Request, "ping", 2, &payload()).unwrap();
        frame[5] ^= 0xff;
        assert!(session.open(&frame).is_err());
    }

    #[test]
    fn rekey_preserves_replay_cache_and_ttl() {
        let now = 1_700_000_000_000;
        let policy = SessionPolicy {
            ttl_ms: 60_000,
            idle_timeout_ms: 60_000,
            rekey_interval_ms: 10_000,
        };
        let mut session = session(now, policy);
        session.set_clock(move || now);
        let frame = session.seal(Kind::Request, "ping", 1, &payload()).unwrap();
        session.open(&frame).unwrap();
        let expires = session.expires_ms;
        session.rotate([4u8; 32], [4u8; 32], now + 10_000);
        assert_eq!(session.epoch(), 1);
        assert_eq!(session.expires_ms, expires);
        assert!(matches!(session.open(&frame), Err(Error::FrameReplay)));
    }

    #[test]
    fn auth_proof_round_trip() {
        let now = 1_700_000_000_000;
        let session = session(now, SessionPolicy::default());
        let proof = session.auth_proof(now);
        session.verify_auth_proof(&proof, now).unwrap();
        assert!(
            session
                .verify_auth_proof(&proof, now + 10 * 60 * 1000)
                .is_err()
        );
        assert!(session.verify_auth_proof(&(proof + "00"), now).is_err());
    }

    #[test]
    fn policy_expiry() {
        let now = 1_700_000_000_000;
        let policy = SessionPolicy {
            ttl_ms: 60_000,
            idle_timeout_ms: 10_000,
            rekey_interval_ms: 10_000,
        };
        let session = session(now, policy);
        assert!(!session.expired(now + 9_000));
        assert!(session.expired(now + 11_000));
        assert!(session.expired(now + 61_000));
        assert!(session.needs_rekey(now + 10_000));
    }
}
