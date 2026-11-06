//! Exact key/value memory with deterministic nearest-position lookup.
//!
//! The name is an architectural analogy only; this module does not claim to
//! reproduce biological hippocampal or small-world network properties.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CognitiveVector {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl CognitiveVector {
    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub fn is_finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }

    pub fn distance(self, other: Self) -> f64 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2) + (self.z - other.z).powi(2))
            .sqrt()
    }
}

impl std::ops::Add for CognitiveVector {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        Self::new(self.x + other.x, self.y + other.y, self.z + other.z)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MemoryError {
    NonFinitePosition,
    StartNotFound,
}

impl Display for MemoryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonFinitePosition => f.write_str("cognitive position must be finite"),
            Self::StartNotFound => f.write_str("path-integration start key was not found"),
        }
    }
}

impl Error for MemoryError {}

#[derive(Clone, Debug)]
struct MemoryEntry<V> {
    value: V,
    position: CognitiveVector,
}

/// A deterministic memory map. Retrieval by key is exact; navigation by vector
/// returns the closest stored key with a deterministic key-order tie break.
pub struct HippocampalMemory<K, V> {
    entries: BTreeMap<K, MemoryEntry<V>>,
}

impl<K: Ord, V> Default for HippocampalMemory<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord, V> HippocampalMemory<K, V> {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<K: Ord + Clone, V: Clone> HippocampalMemory<K, V> {
    pub fn encode(
        &mut self,
        key: K,
        value: V,
        position: CognitiveVector,
    ) -> Result<(), MemoryError> {
        if !position.is_finite() {
            return Err(MemoryError::NonFinitePosition);
        }
        self.entries.insert(key, MemoryEntry { value, position });
        Ok(())
    }

    pub fn retrieve(&self, key: &K) -> Option<V> {
        self.entries.get(key).map(|entry| entry.value.clone())
    }

    pub fn position(&self, key: &K) -> Option<CognitiveVector> {
        self.entries.get(key).map(|entry| entry.position)
    }

    pub fn nearest(&self, target: CognitiveVector) -> Result<Option<(K, f64)>, MemoryError> {
        if !target.is_finite() {
            return Err(MemoryError::NonFinitePosition);
        }
        Ok(self
            .entries
            .iter()
            .map(|(key, entry)| (key.clone(), entry.position.distance(target)))
            .min_by(|left, right| {
                left.1
                    .total_cmp(&right.1)
                    .then_with(|| left.0.cmp(&right.0))
            }))
    }

    pub fn path_integrate(
        &self,
        start: &K,
        displacement: CognitiveVector,
    ) -> Result<Option<K>, MemoryError> {
        let start_position = self.position(start).ok_or(MemoryError::StartNotFound)?;
        let target = start_position + displacement;
        Ok(self.nearest(target)?.map(|(key, _)| key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retrieves_real_encoded_values() {
        let mut memory = HippocampalMemory::new();
        memory
            .encode("theorem", 42, CognitiveVector::new(1.0, 0.0, 0.0))
            .unwrap();
        assert_eq!(memory.retrieve(&"theorem"), Some(42));
        assert_eq!(memory.retrieve(&"missing"), None);
    }

    #[test]
    fn navigation_uses_nearest_position_with_stable_tie_break() {
        let mut memory = HippocampalMemory::new();
        memory
            .encode("a", 1, CognitiveVector::new(0.0, 0.0, 0.0))
            .unwrap();
        memory
            .encode("b", 2, CognitiveVector::new(2.0, 0.0, 0.0))
            .unwrap();
        memory
            .encode("c", 3, CognitiveVector::new(4.0, 0.0, 0.0))
            .unwrap();
        assert_eq!(
            memory
                .path_integrate(&"a", CognitiveVector::new(1.4, 0.0, 0.0))
                .unwrap(),
            Some("b")
        );
        assert_eq!(
            memory
                .path_integrate(&"a", CognitiveVector::new(1.0, 0.0, 0.0))
                .unwrap(),
            Some("a")
        );
    }

    #[test]
    fn rejects_nan_and_missing_start() {
        let mut memory = HippocampalMemory::new();
        assert_eq!(
            memory.encode("bad", 0, CognitiveVector::new(f64::NAN, 0.0, 0.0)),
            Err(MemoryError::NonFinitePosition)
        );
        assert_eq!(
            memory.path_integrate(&"missing", CognitiveVector::default()),
            Err(MemoryError::StartNotFound)
        );
    }
}
