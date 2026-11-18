# nmt-protocol-rust

Rust-клиент протокола **NMT v2**.

Крейт: `nmt-protocol-rust`, библиотека: `nmt`.

Клиент умеет:

- NMTB-кодирование и декодирование;
- проверку сертификата сервера по pinned issuer-ключам;
- гибридный handshake **X25519 + ML-KEM-1024**;
- AEAD-кадры **ChaCha20-Poly1305**;
- replay-защиту и absolute/idle TTL;
- in-band rekey;
- WebSocket upgrade proof;
- HTTP-вызовы `/v1/handshake`, `/v1/rpc`;
- WebSocket `/v1/events` с автоматической обработкой серверного `session.rekey`.

Серверной части в этом крейте нет: сервер, выдача сертификатов, private keys
и HTTP/WebSocket серверная реализация удалены. Сертификаты и ключи
генерируются внешним инструментом, например Go-утилитой
[`nmt-issuer-gen`](../nmt-protocol-go/cmd/nmt-issuer-gen).

## Документация протокола

- [`NMT_SECURE_PROTOCOL.md`](../nmt-protocol-go/docs/NMT_SECURE_PROTOCOL.md) —
  формат, сертификаты, handshake, кадры.
- [`NMT_THREAT_MODEL.md`](../nmt-protocol-go/docs/NMT_THREAT_MODEL.md) —
  модель угроз и ограничения.

## Криптография

| Назначение | Алгоритм |
| --- | --- |
| Обмен ключами | X25519 + ML-KEM-1024 |
| Аутентификация сервера | secp256k1 ECDSA + ML-DSA-65 |
| KDF | HKDF-SHA-256 |
| Шифрование кадров | ChaCha20-Poly1305 |
| Хеш transcript | SHA-256 |
| WebSocket proof | HMAC-SHA-256 |

Клиент анонимный: сертификат подтверждает только сервер. Приложение
аутентифицирует пользователя/устройство поверх NMT RPC.

## Структура

```text
src/nmtb.rs          NMTB codec
src/keys.rs          pinned server public keys и проверка подписей
src/certificate.rs   разбор и проверка NMT-сертификата
src/handshake.rs     клиентский handshake
src/session.rs       сессия, кадры, replay, rekey state
src/rekey.rs         клиентский in-band rekey
src/client.rs        HTTP + WebSocket клиент
src/error.rs         ошибки
src/util.rs          timestamps и transcript helpers
```

## Использование

```rust
use nmt::Client;
use nmt::keys::parse_server_public_keys;
use nmt::nmtb::Value;

let issuer = parse_server_public_keys(&issuer_secp, &issuer_mldsa)?;

let mut client = Client::new("http://127.0.0.1:8080", issuer)?
    .with_server_id("server-1");

client.handshake()?;

// Любой RPC-метод.
let pong = client.ping()?;
let response = client.call("env.info", &Value::map(Default::default()))?;

// Подписка на события. Внутренний session.rekey обрабатывается автоматически.
let events = client.events()?;
for event in events {
    let event = event?;
    println!("{event:?}");
}

// Ротация по серверной политике.
if client.needs_rekey() {
    client.rekey()?;
}

client.logout()?;
```

`Client::call` работает с `nmtb::Value`. Это нижний уровень, на котором
удобно строить собственные типизированные обёртки.

## Rekey

Политика задаётся сервером и приходит в handshake:

- `rekey_messages` — после скольких application-запросов менять ключи;
- `rekey_interval_ms` — верхняя граница по времени.

Клиент не может ускорить rekey: `Client::rekey` — no-op, пока политика не
разрешит. Когда сервер публикует `session.rekey`, `EventStream` выполняет
rekey автоматически и не отдаёт это событие приложению.

## Требования

- Rust **1.87+**;
- Windows/Linux/macOS.

## Сборка и тесты

```powershell
cargo build
cargo test
cargo clippy --all-targets
```

## Ограничения

- только клиент;
- сертификаты и приватные ключи не генерируются;
- typed RPC на уровне структур пока не портирован — API использует
  `nmtb::Value`.
