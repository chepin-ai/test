use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

/// Parse a JSON value while rejecting duplicate member names at every object
/// depth. Keys are compared after JSON escape decoding.
///
/// This is a uniqueness gate inspired by I-JSON/JCS input requirements, not an
/// implementation of RFC 8785 canonical serialization.
pub fn value_from_str(input: &str) -> Result<Value, serde_json::Error> {
    let StrictValue(value) = serde_json::from_str(input)?;
    Ok(value)
}

pub fn value_from_slice(input: &[u8]) -> Result<Value, serde_json::Error> {
    let StrictValue(value) = serde_json::from_slice(input)?;
    Ok(value)
}

pub fn from_str<T: DeserializeOwned>(input: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(value_from_str(input)?)
}

pub fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_value(value_from_slice(input)?)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictValueVisitor;

        impl<'de> Visitor<'de> for StrictValueVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON value with unique object member names")
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

            fn visit_some<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
                while let Some(StrictValue(value)) = sequence.next_element::<StrictValue>()? {
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
                    let StrictValue(value) = access.next_value::<StrictValue>()?;
                    object.insert(key, value);
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictValueVisitor)
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
}
