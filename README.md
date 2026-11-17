# nmt-protocol-rust

Rust port of the **NMT v2 protocol core** from
[`nmt-protocol-go`](../nmt-protocol-go).

Scope: only the protocol library.

- NMTB canonical binary format;
- secp256k1 ECDSA + ML-DSA-65 keys and signatures;
- NMT certificates (issuer/leaf, no X.509);
- hybrid X25519 + ML-KEM-1024 handshake;
- ChaCha20-Poly1305 frames with encrypted inner headers;
- replay protection, session policy and in-band rekey;
- WebSocket upgrade proof primitives.

Not included by request:

- HTTP/WebSocket server;
- HTTP/WebSocket client;
- `nmt-issuer-gen` CLI.

## Crypto

| Purpose | Algorithm |
| --- | --- |
| Key exchange | X25519 + ML-KEM-1024 |
| Certificate and handshake signatures | secp256k1 ECDSA + ML-DSA-65 |
| KDF | HKDF-SHA-256 |
| Session AEAD | ChaCha20-Poly1305 |
| Transcript hash | SHA-256 |
| WebSocket proof | HMAC-SHA-256 |

Both signature schemes are mandatory.

## Modules

```text
src/nmtb.rs          canonical NMTB codec
src/keys.rs          server keys and hybrid signatures
src/certificate.rs   NMT issuer/leaf certificates
src/handshake.rs     hybrid handshake
src/session.rs       frames, replay, policy, upgrade proof
src/rekey.rs         in-band rekey
```

## Usage

### NMTB

```rust
use std::collections::BTreeMap;
use nmt::nmtb::{marshal, unmarshal, Value};

let mut map = BTreeMap::new();
map.insert("hello".to_string(), Value::String("world".to_string()));
let value = Value::Map(map);

let bytes = marshal(&value)?;
assert_eq!(unmarshal(&bytes)?, value);
```

### Keys and certificate

```rust
use nmt::certificate::Certificate;
use nmt::keys::ServerKeys;

let now = 1_700_000_000_000i64;
let issuer = ServerKeys::generate()?;
let leaf = ServerKeys::generate()?;

let certificate = Certificate::issue(
    &leaf,
    &issuer,
    "server-1",
    now - 60_000,
    now + 3_600_000,
)?;
let certificate_bytes = certificate.marshal()?;
let certificate = Certificate::parse(&certificate_bytes)?;
certificate.verify(&issuer.public(), now)?;
```

### Handshake

```rust
use nmt::handshake::{server_handshake, ClientHandshake, ServerHandshakeOptions};
use nmt::session::SessionPolicy;

let (mut client, client_hello) =
    ClientHandshake::new(issuer.public(), now, "server-1")?;

let (server_hello, mut server_session) = server_handshake(
    &client_hello,
    ServerHandshakeOptions {
        keys: &leaf,
        certificate: &certificate_bytes,
        replay_seen: None,
        now_ms: now,
        policy: SessionPolicy::default(),
    },
)?;

let mut client_session = client.finish(&server_hello)?;
assert_eq!(client_session.id, server_session.id);
```

### Encrypted frame

```rust
use nmt::session::Kind;
use nmt::nmtb::Value;

let frame = client_session.seal(Kind::Request, "ping", 1, &Value::Null)?;
let request = server_session.open(&frame)?;
assert_eq!(request.method, "ping");
```

### Rekey

```rust
use nmt::rekey::{server_rekey, RekeyClient};

let (mut rekey, payload) =
    RekeyClient::new(&client_session, leaf.public(), now)?;

let frame = client_session.seal(Kind::Request, "session.rekey", 2, &payload)?;
let request = server_session.open(&frame)?;

let result = server_rekey(&server_session, &request.payload, &leaf, now)?;
let response_frame =
    server_session.seal(Kind::Response, "session.rekey", 2, &result.response)?;
let response = client_session.open(&response_frame)?;

rekey.finish(&mut client_session, &response.payload)?;
server_session.rotate(result.send_key, result.recv_key, now);
```

## Compatibility

The Rust core is wire-compatible with the Go protocol:

- NMTB tags, varints, canonical maps and limits;
- NMT v2 certificate and handshake field names;
- `NMT2` frame layout and inner header;
- HKDF domains and transcript construction;
- rekey request/response and epoch checks.

Timestamps are `i64` Unix milliseconds. `SessionPolicy` uses milliseconds.

`Session` has an injectable clock for deterministic tests:

```rust
session.set_clock(|| 1_700_000_000_000);
```

## Tests

```powershell
cargo test
cargo clippy --all-targets
```

The test suite covers NMTB round-trips and canonical maps, key
serialization, certificate issue/verify/tamper, handshake, clock skew,
replay, encrypted frames, inner-header hiding, session policy, rekey and
WebSocket proof.
