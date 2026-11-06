//! Cognitive data structures with deterministic behavior.

pub mod hippocampus;
pub mod hypergraph;
pub mod operad;

pub use hippocampus::{CognitiveVector, HippocampalMemory, MemoryError};
pub use hypergraph::{CognitiveHyperGraph, HyperGraphError, MetaRelation, SuperHyperEdge};
pub use operad::{FunctionOperad, Operad, OperadError};
