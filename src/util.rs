use std::collections::BTreeMap;

use crate::error::Error;
use crate::nmtb::Value;

pub(crate) const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

pub(crate) fn signing_input(domain: &[u8], unsigned: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + unsigned.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(unsigned);
    input
}

pub(crate) fn check_timestamp(now_ms: i64, timestamp_ms: i64) -> Result<(), Error> {
    if timestamp_ms == 0 {
        return Err(Error::ClockSkew);
    }
    if (now_ms - timestamp_ms).abs() > MAX_CLOCK_SKEW_MS {
        return Err(Error::ClockSkew);
    }
    Ok(())
}

pub(crate) fn bytes_field(map: &BTreeMap<String, Value>, key: &str) -> Option<Vec<u8>> {
    map.get(key)?.as_bytes().map(ToOwned::to_owned)
}

pub(crate) fn int_field(map: &BTreeMap<String, Value>, key: &str) -> Option<i64> {
    map.get(key)?.as_int()
}

pub(crate) fn string_field(map: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    map.get(key)?.as_str().map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_window() {
        assert!(check_timestamp(1000, 1000).is_ok());
        assert!(check_timestamp(1000, 1000 + MAX_CLOCK_SKEW_MS).is_ok());
        assert!(check_timestamp(1000, 1000 + MAX_CLOCK_SKEW_MS + 1).is_err());
        assert!(check_timestamp(1000, 0).is_err());
    }
}
