use serde::de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use serde_json::{Map, Number, Value};
use std::cell::Cell;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::rc::Rc;

pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_NODES: usize = 16_384;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JsonLimits {
    pub max_depth: usize,
    pub max_nodes: usize,
}

impl JsonLimits {
    pub const DEFAULT: Self = Self {
        max_depth: MAX_JSON_DEPTH,
        max_nodes: MAX_JSON_NODES,
    };
}

/// Parse a JSON value with duplicate-member, depth, and whole-document node
/// gates. Object keys are not separate values; every container and scalar is.
/// This is an input hardening gate, not RFC 8785 canonical serialization.
pub fn value_from_str(input: &str) -> Result<Value, serde_json::Error> {
    value_from_slice_with_limits(input.as_bytes(), JsonLimits::DEFAULT)
}

pub fn value_from_slice(input: &[u8]) -> Result<Value, serde_json::Error> {
    value_from_slice_with_limits(input, JsonLimits::DEFAULT)
}

pub fn value_from_slice_with_limits(
    input: &[u8],
    limits: JsonLimits,
) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let StrictValue(value) = StrictValueSeed::new(limits).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

pub fn from_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(value_from_str(input)?)
}

pub fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_value(value_from_slice(input)?)
}

/// Read at most `max_bytes + 1` bytes, rejecting both a large initial metadata
/// length and a file that grows while it is being read.
pub fn from_path<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> io::Result<T> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON input exceeds {max_bytes} bytes"),
        ));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON input exceeds {max_bytes} bytes"),
        ));
    }
    from_slice(&bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

struct StrictValue(Value);

#[derive(Clone)]
struct StrictValueSeed {
    depth: usize,
    nodes: Rc<Cell<usize>>,
    limits: JsonLimits,
}

impl StrictValueSeed {
    fn new(limits: JsonLimits) -> Self {
        Self {
            depth: 1,
            nodes: Rc::new(Cell::new(0)),
            limits,
        }
    }

    fn child(&self) -> Self {
        Self {
            depth: self.depth + 1,
            nodes: Rc::clone(&self.nodes),
            limits: self.limits,
        }
    }
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = StrictValue;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        if self.depth > self.limits.max_depth {
            return Err(serde::de::Error::custom(format!(
                "JSON depth budget exceeded: limit={}, next_depth={}",
                self.limits.max_depth, self.depth
            )));
        }
        let next = self.nodes.get().checked_add(1).ok_or_else(|| {
            serde::de::Error::custom("JSON node counter overflowed its host representation")
        })?;
        if next > self.limits.max_nodes {
            return Err(serde::de::Error::custom(format!(
                "JSON node budget exceeded: limit={}, next_node={next}",
                self.limits.max_nodes
            )));
        }
        self.nodes.set(next);
        deserializer.deserialize_any(StrictValueVisitor { seed: self })
    }
}

struct StrictValueVisitor {
    seed: StrictValueSeed,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value with unique members and bounded depth and nodes")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(StrictValue(value)) = sequence.next_element_seed(self.seed.child())? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
        let mut object = Map::with_capacity(access.size_hint().unwrap_or(0));
        while let Some(key) = access.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON object member: {key:?}"
                )));
            }
            let StrictValue(value) = access.next_value_seed(self.seed.child())?;
            object.insert(key, value);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_nested_unique_objects_and_escape_decoding() {
        let value = value_from_str(r#"{"a":1,"\u0062":[{"c":true}]}"#).unwrap();
        assert_eq!(value, json!({"a": 1, "b": [{"c": true}]}));
    }

    #[test]
    fn rejects_duplicate_members_at_every_depth() {
        for input in [
            r#"{"a":1,"a":2}"#,
            r#"{"outer":[{"a":1,"a":2}]}"#,
            r#"{"a":1,"\u0061":2}"#,
        ] {
            let error = value_from_str(input).unwrap_err().to_string();
            assert!(error.contains("duplicate JSON object member"), "{error}");
        }
    }

    #[test]
    fn typed_entry_uses_the_same_uniqueness_gate() {
        let result = from_str::<Value>(r#"{"a":1,"\u0061":2}"#);
        assert!(result.is_err());
    }

    #[test]
    fn exact_default_depth_boundary_is_enforced() {
        let accepted = format!("{}0{}", "[".repeat(63), "]".repeat(63));
        let rejected = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        assert!(value_from_str(&accepted).is_ok());
        let error = value_from_str(&rejected).unwrap_err().to_string();
        assert!(error.contains("JSON depth budget exceeded"), "{error}");
    }

    #[test]
    fn exact_default_node_boundary_is_enforced() {
        let accepted = format!("[{}]", vec!["0"; MAX_JSON_NODES - 1].join(","));
        let rejected = format!("[{}]", vec!["0"; MAX_JSON_NODES].join(","));
        assert!(value_from_str(&accepted).is_ok());
        let error = value_from_str(&rejected).unwrap_err().to_string();
        assert!(error.contains("JSON node budget exceeded"), "{error}");
    }

    #[test]
    fn node_budget_is_shared_across_branches() {
        let input = br#"[[1,2],[3,4]]"#;
        let accepted = JsonLimits {
            max_depth: 3,
            max_nodes: 7,
        };
        let rejected = JsonLimits {
            max_nodes: 6,
            ..accepted
        };
        assert!(value_from_slice_with_limits(input, accepted).is_ok());
        let error = value_from_slice_with_limits(input, rejected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("JSON node budget exceeded"), "{error}");
    }

    #[test]
    fn bounded_file_reader_rejects_oversize_input() {
        let path = std::env::temp_dir().join(format!(
            "asfa-strict-json-oversize-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(&path, b"          ").unwrap();
        let error = from_path::<Value>(&path, 9).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 9 bytes"));
        fs::remove_file(path).unwrap();
    }
}
