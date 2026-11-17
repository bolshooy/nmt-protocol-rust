# nmt-protocol-rust

Rust-порт **ядра протокола NMT v2** из
[`nmt-protocol-go`](../nmt-protocol-go).

Пакет: `nmt-protocol-rust`. Библиотека: `nmt`.

Реализован только протокол:

- канонический бинарный формат **NMTB**;
- ключи и подписи **secp256k1 ECDSA + ML-DSA-65**;
- NMT-сертификаты issuer/leaf, без X.509;
- гибридный handshake **X25519 + ML-KEM-1024**;
- кадры **ChaCha20-Poly1305** с зашифрованными внутренними заголовками;
- replay-защита, политика сессии и in-band rekey;
- примитивы WebSocket upgrade proof.

По запросу **не включены**:

- HTTP/WebSocket server;
- HTTP/WebSocket client;
- CLI `nmt-issuer-gen`.

## Документация протокола

- [`NMT_SECURE_PROTOCOL.md`](../nmt-protocol-go/docs/NMT_SECURE_PROTOCOL.md) —
  устройство протокола, сертификаты, handshake, кадры.
- [`NMT_THREAT_MODEL.md`](../nmt-protocol-go/docs/NMT_THREAT_MODEL.md) —
  модель угроз и остаточные риски.

## Криптография

| Назначение | Алгоритм |
| --- | --- |
| Обмен ключами | X25519 + ML-KEM-1024 |
| Подписи сертификата и handshake | secp256k1 ECDSA + ML-DSA-65 |
| KDF | HKDF-SHA-256 |
| Шифрование сессии | ChaCha20-Poly1305 |
| Хеш transcript | SHA-256 |
| WebSocket proof | HMAC-SHA-256 |

Обе схемы подписи обязательны: клиент проверяет и классическую, и
постквантовую.

## Модули

```text
src/nmtb.rs          канонический NMTB codec
src/keys.rs          ключи сервера и гибридные подписи
src/certificate.rs   NMT issuer/leaf сертификаты
src/handshake.rs     гибридный handshake
src/session.rs       кадры, replay, политика, upgrade proof
src/rekey.rs         in-band rekey
src/error.rs         общий тип ошибок
src/util.rs          timestamps и transcript helpers
```

## Требования

- Rust **1.87+**;
- Windows/Linux/macOS.

## Использование

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

### Ключи и сертификат

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

`not_before` и `not_after` — Unix milliseconds.

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

Клиент анонимный. Сервер подтверждает себя сертификатом, подписанным
запиненным issuer-ключом. `expected_server_id` проверяется, если задан.

### Зашифрованный кадр

```rust
use nmt::session::Kind;
use nmt::nmtb::Value;

let frame = client_session.seal(Kind::Request, "ping", 1, &Value::Null)?;
let request = server_session.open(&frame)?;
assert_eq!(request.method, "ping");
```

Кадр NMT2:

```text
"NMT2" | version | handle[16] | nonce[12] | ciphertext | tag[16]
```

Внутри AEAD:

```text
inner_version | kind | flags | reserved |
request_id | timestamp_ms | method_len | method |
payload_len | NMTB payload
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

Rekey не продлевает абсолютный TTL. Replay-кэш сохраняется при ротации.

## Совместимость с Go

Rust-ядро wire-совместимо с Go-протоколом:

- теги NMTB, varint, канонические map и лимиты;
- имена полей сертификата и handshake NMT v2;
- layout кадра `NMT2` и внутреннего заголовка;
- HKDF-домены и построение transcript;
- rekey request/response и проверка epoch.

Проверено на практике:

- одинаковые NMTB-данные дают одинаковые байты в Go и Rust;
- Rust проверяет сертификат, выпущенный Go;
- Go проверяет сертификат, выпущенный Rust.

Время — `i64` Unix milliseconds. `SessionPolicy` использует миллисекунды.

Для детерминированных тестов можно подменить часы:

```rust
session.set_clock(|| 1_700_000_000_000);
```

## Тесты

```powershell
cargo test
cargo clippy --all-targets
```

Покрыто:

- NMTB round-trip, канонический порядок ключей и лимиты;
- сериализация и восстановление ключей;
- выпуск, парсинг, проверка и подмена сертификата;
- handshake, неверный issuer, неверный `server_id`, clock skew;
- replay handshake и кадров;
- зашифрованные кадры и скрытие внутреннего заголовка;
- политика сессии, TTL и idle timeout;
- rekey, stale epoch и сохранение replay-кэша;
- WebSocket upgrade proof.

Текущий результат:

```text
25 passed; 0 failed
```
