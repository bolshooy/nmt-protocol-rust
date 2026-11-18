//! NMT HTTP/WebSocket client.
//!
//! The client establishes a certificate-authenticated session, sends sealed
//! RPC frames over HTTP and consumes sealed events over WebSocket.

use std::io::Read;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use http::{HeaderValue, Request};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::error::Error;
use crate::handshake::ClientHandshake;
use crate::keys::{ServerPublicKeys, parse_server_public_keys};
use crate::nmtb::{self, Value};
use crate::rekey::RekeyClient;
use crate::session::{Kind, Session};

const HANDSHAKE_PATH: &str = "/v1/handshake";
const RPC_PATH: &str = "/v1/rpc";
const EVENTS_PATH: &str = "/v1/events";
const MAX_HANDSHAKE_BYTES: usize = 2 << 20;
const MAX_FRAME_BYTES: usize = 1 << 20;
const SESSION_HEADER: &str = "X-NMT-Session";
const PROOF_HEADER: &str = "X-NMT-Proof";

/// NMT client. Cloning is cheap and shares the session with event streams.
#[derive(Clone)]
pub struct Client {
    base_url: String,
    http: ureq::Agent,
    issuer: ServerPublicKeys,
    server_keys: Option<ServerPublicKeys>,
    session: Option<Arc<Mutex<Session>>>,
    server_id: Option<String>,
}

impl Client {
    /// Create a client that trusts certificates signed by `issuer`.
    pub fn new(base_url: impl Into<String>, issuer: ServerPublicKeys) -> Result<Self, Error> {
        parse_server_public_keys(&issuer.secp256k1, &issuer.mldsa)?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            http: ureq::agent(),
            issuer,
            server_keys: None,
            session: None,
            server_id: None,
        })
    }

    /// Require the certificate `server_id` to match this value.
    pub fn with_server_id(mut self, server_id: impl Into<String>) -> Self {
        self.server_id = Some(server_id.into());
        self
    }

    /// Perform the hybrid handshake and create a client session.
    pub fn handshake(&mut self) -> Result<(), Error> {
        let now = now_ms();
        let (mut state, hello) = ClientHandshake::new(
            self.issuer.clone(),
            now,
            self.server_id.clone().unwrap_or_default(),
        )?;
        let (status, body) = self.post(HANDSHAKE_PATH, &hello, MAX_HANDSHAKE_BYTES)?;
        if status >= 400 {
            return Err(plain_error(&body, status));
        }
        let session = state.finish(&body)?;
        self.server_keys = state.server_keys().cloned();
        self.session = Some(Arc::new(Mutex::new(session)));
        Ok(())
    }

    /// Verify the encrypted request path.
    pub fn ping(&self) -> Result<Value, Error> {
        self.call("ping", &Value::map(Default::default()))
    }

    /// Invoke an application RPC method.
    pub fn call(&self, method: &str, payload: &Value) -> Result<Value, Error> {
        let session = self.session_arc()?;
        let request_id = next_request_id()?;
        let frame = {
            let mut guard = lock(&session);
            guard.seal(Kind::Request, method, request_id, payload)?
        };
        let (status, body) = self.post(RPC_PATH, &frame, MAX_FRAME_BYTES)?;
        let mut guard = lock(&session);
        if status >= 400 {
            if let Ok(frame) = guard.open(&body) {
                if frame.kind == Kind::Error {
                    return Err(api_error(&frame.payload));
                }
            }
            return Err(plain_error(&body, status));
        }
        let frame = guard.open(&body)?;
        if frame.request_id != request_id {
            return Err(Error::Protocol("response request id mismatch".into()));
        }
        if frame.kind == Kind::Error {
            return Err(api_error(&frame.payload));
        }
        if frame.kind != Kind::Response || frame.method != method {
            return Err(Error::Protocol("unexpected response frame".into()));
        }
        parse_result(&frame.payload)
    }

    /// Rotate keys when the server-owned policy says it is due.
    pub fn rekey(&self) -> Result<(), Error> {
        self.rekey_internal(false)
    }

    /// Start an encrypted event WebSocket.
    pub fn events(&self) -> Result<EventStream, Error> {
        let session = self.session_arc()?;
        let (handle, proof) = {
            let guard = lock(&session);
            (guard.handle_hex(), guard.auth_proof(now_ms()))
        };
        let url = websocket_url(&self.base_url, EVENTS_PATH);
        let mut request = Request::builder()
            .uri(&url)
            .body(())
            .map_err(|err| Error::WebSocket(err.to_string()))?;
        request.headers_mut().insert(
            SESSION_HEADER,
            HeaderValue::from_str(&handle).map_err(|err| Error::WebSocket(err.to_string()))?,
        );
        request.headers_mut().insert(
            PROOF_HEADER,
            HeaderValue::from_str(&proof).map_err(|err| Error::WebSocket(err.to_string()))?,
        );
        let (socket, _) =
            tungstenite::connect(request).map_err(|err| Error::WebSocket(err.to_string()))?;
        Ok(EventStream {
            client: self.clone(),
            session,
            socket,
            done: false,
        })
    }

    /// Revoke the current session.
    pub fn logout(&mut self) -> Result<(), Error> {
        self.call("sessions/current", &Value::map(Default::default()))?;
        self.session = None;
        Ok(())
    }

    /// Whether the server-owned rekey policy says keys should rotate.
    pub fn needs_rekey(&self) -> bool {
        self.session
            .as_ref()
            .map(|session| lock(session).needs_rekey(now_ms()))
            .unwrap_or(false)
    }

    /// Current key epoch, if a session exists.
    pub fn epoch(&self) -> Option<u64> {
        self.session.as_ref().map(|session| lock(session).epoch())
    }

    fn session_arc(&self) -> Result<Arc<Mutex<Session>>, Error> {
        self.session.clone().ok_or(Error::NotAuthenticated)
    }

    fn rekey_internal(&self, force: bool) -> Result<(), Error> {
        let session = self.session_arc()?;
        let server_keys = self
            .server_keys
            .clone()
            .ok_or_else(|| Error::Protocol("server certificate keys are not available".into()))?;
        let request_id = next_request_id()?;
        let (mut state, frame) = {
            let mut guard = lock(&session);
            if !force && !guard.needs_rekey(now_ms()) {
                return Ok(());
            }
            let (state, payload) = RekeyClient::new(&guard, server_keys, now_ms())?;
            let frame = guard.seal(Kind::Request, "session.rekey", request_id, &payload)?;
            (state, frame)
        };
        let (status, body) = self.post(RPC_PATH, &frame, MAX_FRAME_BYTES)?;
        let mut guard = lock(&session);
        if status >= 400 {
            if let Ok(frame) = guard.open(&body) {
                if frame.kind == Kind::Error {
                    return Err(api_error(&frame.payload));
                }
            }
            return Err(plain_error(&body, status));
        }
        let frame = guard.open(&body)?;
        if frame.kind == Kind::Error {
            return Err(api_error(&frame.payload));
        }
        if frame.kind != Kind::Response
            || frame.request_id != request_id
            || frame.method != "session.rekey"
        {
            return Err(Error::Protocol("invalid rekey response".into()));
        }
        state.finish(&mut guard, &frame.payload)
    }

    fn post(&self, path: &str, body: &[u8], limit: usize) -> Result<(u16, Vec<u8>), Error> {
        let url = format!("{}{}", self.base_url, path);
        match self
            .http
            .post(&url)
            .set("Content-Type", "application/x-nmt")
            .send_bytes(body)
        {
            Ok(response) => {
                let status = response.status();
                let body = read_limited(response.into_reader(), limit)?;
                Ok((status, body))
            }
            Err(ureq::Error::Status(status, response)) => {
                let body = read_limited(response.into_reader(), limit)?;
                Ok((status, body))
            }
            Err(error) => Err(Error::Http(error.to_string())),
        }
    }
}

/// Blocking iterator over NMT events. Internal `session.rekey` events are
/// handled transparently and are not yielded.
pub struct EventStream {
    client: Client,
    session: Arc<Mutex<Session>>,
    socket: WebSocket<MaybeTlsStream<std::net::TcpStream>>,
    done: bool,
}

impl Iterator for EventStream {
    type Item = Result<Value, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.socket.read() {
                Ok(Message::Binary(data)) => {
                    let frame = match lock(&self.session).open(&data) {
                        Ok(frame) => frame,
                        Err(error) => {
                            self.done = true;
                            return Some(Err(error));
                        }
                    };
                    if frame.kind != Kind::Event {
                        continue;
                    }
                    let handle = lock(&self.session).handle_hex();
                    if is_rekey_event(&frame.payload, &handle) {
                        if let Err(error) = self.client.rekey_internal(true) {
                            self.done = true;
                            return Some(Err(error));
                        }
                        continue;
                    }
                    return Some(Ok(frame.payload));
                }
                Ok(Message::Ping(payload)) => {
                    if let Err(error) = self.socket.send(Message::Pong(payload)) {
                        self.done = true;
                        return Some(Err(Error::WebSocket(error.to_string())));
                    }
                }
                Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
                Ok(Message::Text(_)) => continue,
                Ok(Message::Close(_)) | Err(_) => {
                    self.done = true;
                    return None;
                }
            }
        }
    }
}

fn lock(session: &Arc<Mutex<Session>>) -> MutexGuard<'_, Session> {
    session
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn is_rekey_event(payload: &Value, handle: &str) -> bool {
    let Some(map) = payload.as_map() else {
        return false;
    };
    if map.get("event").and_then(Value::as_str) != Some("session.rekey") {
        return false;
    }
    map.get("data")
        .and_then(Value::as_map)
        .and_then(|data| data.get("handle"))
        .and_then(Value::as_str)
        == Some(handle)
}

fn parse_result(payload: &Value) -> Result<Value, Error> {
    let map = payload
        .as_map()
        .ok_or_else(|| Error::Protocol("expected a response map".into()))?;
    if matches!(map.get("ok").and_then(Value::as_bool), Some(false)) {
        return Err(api_error(payload));
    }
    Ok(map.get("result").cloned().unwrap_or(Value::null()))
}

fn api_error(payload: &Value) -> Error {
    let error = payload
        .as_map()
        .and_then(|map| map.get("error"))
        .and_then(Value::as_map);
    let code = error
        .and_then(|map| map.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("error")
        .to_owned();
    let message = error
        .and_then(|map| map.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("request failed")
        .to_owned();
    Error::Api { code, message }
}

fn plain_error(body: &[u8], status: u16) -> Error {
    if let Ok(value) = nmtb::unmarshal(body) {
        if value.get("error").is_some() {
            return api_error(&value);
        }
    }
    Error::Http(format!("server returned HTTP {status}"))
}

fn read_limited(reader: impl Read, limit: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::Http(err.to_string()))?;
    Ok(bytes)
}

fn next_request_id() -> Result<u64, Error> {
    let bytes = crate::keys::random_bytes(8)?;
    Ok(u64::from_le_bytes(bytes.try_into().expect("8 bytes")))
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

fn websocket_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}{path}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}{path}")
    } else {
        format!("{base}{path}")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn builds_websocket_urls() {
        assert_eq!(
            websocket_url("http://127.0.0.1:8080/", "/v1/events"),
            "ws://127.0.0.1:8080/v1/events"
        );
        assert_eq!(
            websocket_url("https://example.test", "/v1/events"),
            "wss://example.test/v1/events"
        );
    }

    #[test]
    fn parses_result_and_api_error() {
        let mut result = BTreeMap::new();
        result.insert("ok".into(), Value::Bool(true));
        result.insert("result".into(), Value::String("fine".into()));
        assert_eq!(
            parse_result(&Value::Map(result)).unwrap(),
            Value::String("fine".into())
        );

        let mut error = BTreeMap::new();
        error.insert("code".into(), Value::String("invalid_request".into()));
        error.insert("message".into(), Value::String("bad".into()));
        let mut response = BTreeMap::new();
        response.insert("ok".into(), Value::Bool(false));
        response.insert("error".into(), Value::Map(error));
        match parse_result(&Value::Map(response)) {
            Err(Error::Api { code, message }) => {
                assert_eq!(code, "invalid_request");
                assert_eq!(message, "bad");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn filters_rekey_events_by_handle() {
        let mut data = BTreeMap::new();
        data.insert("handle".into(), Value::String("abcd".into()));
        let mut event = BTreeMap::new();
        event.insert("event".into(), Value::String("session.rekey".into()));
        event.insert("data".into(), Value::Map(data));
        let payload = Value::Map(event);
        assert!(is_rekey_event(&payload, "abcd"));
        assert!(!is_rekey_event(&payload, "other"));
    }
}
