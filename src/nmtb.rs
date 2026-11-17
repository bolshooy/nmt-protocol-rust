//! NMTB: deterministic binary encoding used by the NMT protocol.
//!
//! The wire format is intentionally small and canonical:
//! - one tag byte per value;
//! - unsigned LEB128 lengths and integers;
//! - map keys sorted by UTF-8 bytes, duplicates rejected;
//! - strict limits on depth, item count and total size.

use std::collections::BTreeMap;
use std::fmt;

/// NMTB type tags. Values match the Go implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Null = 0,
    False = 1,
    True = 2,
    Int = 3,
    Uint = 4,
    Float = 5,
    String = 6,
    Bytes = 7,
    Array = 8,
    Map = 9,
    Timestamp = 10,
    Uuid = 11,
}

impl Kind {
    fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Null,
            1 => Self::False,
            2 => Self::True,
            3 => Self::Int,
            4 => Self::Uint,
            5 => Self::Float,
            6 => Self::String,
            7 => Self::Bytes,
            8 => Self::Array,
            9 => Self::Map,
            10 => Self::Timestamp,
            11 => Self::Uuid,
            _ => return None,
        })
    }
}

/// One typed NMTB value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
    Timestamp(i64),
    Uuid([u8; 16]),
}

impl Value {
    pub fn null() -> Self {
        Self::Null
    }

    pub fn bool(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn int(value: i64) -> Self {
        Self::Int(value)
    }

    pub fn uint(value: u64) -> Self {
        Self::Uint(value)
    }

    pub fn float(value: f64) -> Self {
        Self::Float(value)
    }

    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    pub fn array(value: Vec<Value>) -> Self {
        Self::Array(value)
    }

    pub fn map(value: BTreeMap<String, Value>) -> Self {
        Self::Map(value)
    }

    pub fn timestamp_millis(value: i64) -> Self {
        Self::Timestamp(value)
    }

    pub fn uuid(value: [u8; 16]) -> Self {
        Self::Uuid(value)
    }

    pub fn kind(&self) -> Kind {
        match self {
            Self::Null => Kind::Null,
            Self::Bool(false) => Kind::False,
            Self::Bool(true) => Kind::True,
            Self::Int(_) => Kind::Int,
            Self::Uint(_) => Kind::Uint,
            Self::Float(_) => Kind::Float,
            Self::String(_) => Kind::String,
            Self::Bytes(_) => Kind::Bytes,
            Self::Array(_) => Kind::Array,
            Self::Map(_) => Kind::Map,
            Self::Timestamp(_) => Kind::Timestamp,
            Self::Uuid(_) => Kind::Uuid,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(value) | Self::Timestamp(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::Map(value) => Some(value),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?.get(key)
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

/// Decoder/encoder resource limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_depth: usize,
    pub max_items: usize,
    pub max_string: usize,
    pub max_blob: usize,
    pub max_total: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_items: 10_000,
            max_string: 1 << 20,
            max_blob: 1 << 20,
            max_total: 4 << 20,
        }
    }
}

/// NMTB error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn error(message: impl Into<String>) -> Error {
    Error(message.into())
}

/// Encode a value using default limits.
pub fn marshal(value: &Value) -> Result<Vec<u8>, Error> {
    marshal_with_limits(value, Limits::default())
}

/// Encode a value with explicit limits.
pub fn marshal_with_limits(value: &Value, limits: Limits) -> Result<Vec<u8>, Error> {
    let mut encoder = Encoder {
        out: Vec::new(),
        limits,
    };
    encoder.value(value, 0)?;
    if encoder.out.len() > limits.max_total {
        return Err(error(format!(
            "nmtb: encoded value exceeds {} bytes",
            limits.max_total
        )));
    }
    Ok(encoder.out)
}

/// Decode a canonical NMTB value using default limits.
pub fn unmarshal(data: &[u8]) -> Result<Value, Error> {
    unmarshal_with_limits(data, Limits::default())
}

/// Decode a canonical NMTB value with explicit limits.
pub fn unmarshal_with_limits(data: &[u8], limits: Limits) -> Result<Value, Error> {
    if data.len() > limits.max_total {
        return Err(error(format!(
            "nmtb: input exceeds {} bytes",
            limits.max_total
        )));
    }
    let mut decoder = Decoder {
        data,
        pos: 0,
        limits,
    };
    let value = decoder.value(0)?;
    if decoder.pos != data.len() {
        return Err(error("nmtb: trailing bytes"));
    }
    Ok(value)
}

struct Encoder {
    out: Vec<u8>,
    limits: Limits,
}

impl Encoder {
    fn value(&mut self, value: &Value, depth: usize) -> Result<(), Error> {
        if depth > self.limits.max_depth {
            return Err(error("nmtb: maximum depth exceeded"));
        }
        if self.out.len() > self.limits.max_total {
            return Err(error("nmtb: encoded value is too large"));
        }
        self.out.push(value.kind() as u8);
        match value {
            Value::Null | Value::Bool(_) => {}
            Value::Int(number) | Value::Timestamp(number) => {
                self.out.extend_from_slice(&uvarint(zigzag(*number)));
            }
            Value::Uint(number) => self.out.extend_from_slice(&uvarint(*number)),
            Value::Float(number) => {
                self.out.extend_from_slice(&number.to_bits().to_le_bytes());
            }
            Value::String(text) => {
                if text.len() > self.limits.max_string {
                    return Err(error("nmtb: string is too large"));
                }
                // Rust strings are always valid UTF-8.
                self.write_blob(text.as_bytes());
            }
            Value::Bytes(blob) => {
                if blob.len() > self.limits.max_blob {
                    return Err(error("nmtb: bytes are too large"));
                }
                self.write_blob(blob);
            }
            Value::Array(items) => {
                if items.len() > self.limits.max_items {
                    return Err(error("nmtb: array has too many items"));
                }
                self.out.extend_from_slice(&uvarint(items.len() as u64));
                for item in items {
                    self.value(item, depth + 1)?;
                }
            }
            Value::Map(map) => {
                if map.len() > self.limits.max_items {
                    return Err(error("nmtb: map has too many items"));
                }
                for key in map.keys() {
                    if key.is_empty() {
                        return Err(error("nmtb: empty map keys are not allowed"));
                    }
                    if key.len() > self.limits.max_string {
                        return Err(error("nmtb: map key is too large"));
                    }
                }
                self.out.extend_from_slice(&uvarint(map.len() as u64));
                for (key, item) in map {
                    self.write_blob(key.as_bytes());
                    self.value(item, depth + 1)?;
                }
            }
            Value::Uuid(uuid) => self.out.extend_from_slice(uuid),
        }
        Ok(())
    }

    fn write_blob(&mut self, data: &[u8]) {
        self.out.extend_from_slice(&uvarint(data.len() as u64));
        self.out.extend_from_slice(data);
    }
}

struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
    limits: Limits,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > self.limits.max_depth {
            return Err(error("nmtb: maximum depth exceeded"));
        }
        let tag = self.byte()?;
        let kind =
            Kind::from_byte(tag).ok_or_else(|| error(format!("nmtb: unknown value kind {tag}")))?;
        Ok(match kind {
            Kind::Null => Value::Null,
            Kind::False => Value::Bool(false),
            Kind::True => Value::Bool(true),
            Kind::Int => Value::Int(unzigzag(self.uvarint()?)),
            Kind::Uint => Value::Uint(self.uvarint()?),
            Kind::Float => {
                let raw = self.take(8)?;
                let bits = u64::from_le_bytes(raw.try_into().expect("8 bytes"));
                Value::Float(f64::from_bits(bits))
            }
            Kind::String => {
                let raw = self.blob(self.limits.max_string)?;
                let text = std::str::from_utf8(raw)
                    .map_err(|_| error("nmtb: string is not valid UTF-8"))?;
                Value::String(text.to_owned())
            }
            Kind::Bytes => Value::Bytes(self.blob(self.limits.max_blob)?.to_vec()),
            Kind::Array => {
                let count = self.count()?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            Kind::Map => {
                let count = self.count()?;
                let mut map = BTreeMap::new();
                let mut previous: Option<String> = None;
                for _ in 0..count {
                    let raw = self.blob(self.limits.max_string)?;
                    let key = std::str::from_utf8(raw)
                        .map_err(|_| error("nmtb: map key is not valid UTF-8"))?
                        .to_owned();
                    if key.is_empty() {
                        return Err(error("nmtb: empty map keys are not allowed"));
                    }
                    if let Some(last) = &previous {
                        if key.as_bytes() <= last.as_bytes() {
                            return Err(error("nmtb: map keys are not strictly sorted"));
                        }
                    }
                    previous = Some(key.clone());
                    let item = self.value(depth + 1)?;
                    map.insert(key, item);
                }
                Value::Map(map)
            }
            Kind::Timestamp => Value::Timestamp(unzigzag(self.uvarint()?)),
            Kind::Uuid => {
                let raw = self.take(16)?;
                Value::Uuid(raw.try_into().expect("16 bytes"))
            }
        })
    }

    fn count(&mut self) -> Result<usize, Error> {
        let count = self.uvarint()?;
        if count > self.limits.max_items as u64 {
            return Err(error("nmtb: collection has too many items"));
        }
        Ok(count as usize)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        if self.pos >= self.data.len() {
            return Err(error("nmtb: unexpected end of input"));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn uvarint(&mut self) -> Result<u64, Error> {
        let mut value = 0u64;
        for shift in (0..=63).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(error("nmtb: invalid varint"))
    }

    fn blob(&mut self, max: usize) -> Result<&[u8], Error> {
        let length = self.uvarint()?;
        if length > max as u64 {
            return Err(error("nmtb: blob is too large"));
        }
        self.take(length as usize)
    }

    fn take(&mut self, length: usize) -> Result<&[u8], Error> {
        let end = self
            .pos
            .checked_add(length)
            .ok_or_else(|| error("nmtb: unexpected end of input"))?;
        if end > self.data.len() {
            return Err(error("nmtb: unexpected end of input"));
        }
        let value = &self.data[self.pos..end];
        self.pos = end;
        Ok(value)
    }
}

fn uvarint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

fn unzigzag(value: u64) -> i64 {
    ((value >> 1) as i64) ^ -((value & 1) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        )
    }

    #[test]
    fn round_trip_all_types() {
        let value = map(&[
            ("null", Value::Null),
            ("false", Value::Bool(false)),
            ("true", Value::Bool(true)),
            ("int", Value::Int(-42)),
            ("uint", Value::Uint(42)),
            ("float", Value::Float(3.5)),
            ("string", Value::String("hello".into())),
            ("bytes", Value::Bytes(vec![1, 2, 3])),
            ("array", Value::Array(vec![Value::Int(1), Value::Int(2)])),
            ("timestamp", Value::Timestamp(1_700_000_000_000)),
            ("uuid", Value::Uuid([7; 16])),
        ]);
        let encoded = marshal(&value).unwrap();
        let decoded = unmarshal(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn map_is_canonical() {
        let value = map(&[("b", Value::Int(2)), ("a", Value::Int(1))]);
        let encoded = marshal(&value).unwrap();
        let decoded = unmarshal(&encoded).unwrap();
        assert_eq!(decoded, value);
        // The encoder writes keys in sorted order: "a" before "b".
        let a = encoded.windows(1).position(|w| w == b"a").unwrap();
        let b = encoded.windows(1).position(|w| w == b"b").unwrap();
        assert!(a < b);
    }

    #[test]
    fn known_encoding_matches_go() {
        let value = map(&[("a", Value::Int(1)), ("b", Value::String("x".into()))]);
        assert_eq!(
            marshal(&value).unwrap(),
            vec![9, 2, 1, b'a', 3, 2, 1, b'b', 6, 1, b'x']
        );
    }

    #[test]
    fn rejects_duplicate_and_unsorted_keys() {
        // map { b: 1, a: 2 } with keys in wrong order
        let mut encoded = vec![Kind::Map as u8, 2];
        encoded.push(1);
        encoded.push(b'b');
        encoded.push(Kind::Int as u8);
        encoded.push(2);
        encoded.push(1);
        encoded.push(b'a');
        encoded.push(Kind::Int as u8);
        encoded.push(4);
        assert!(unmarshal(&encoded).is_err());
    }

    #[test]
    fn rejects_limits() {
        let limits = Limits {
            max_items: 1,
            ..Limits::default()
        };
        let value = Value::Array(vec![Value::Int(1), Value::Int(2)]);
        assert!(marshal_with_limits(&value, limits).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = marshal(&Value::Int(1)).unwrap();
        encoded.push(0);
        assert!(unmarshal(&encoded).is_err());
    }
}
