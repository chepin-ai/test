//! 认知计算层

pub mod hypergraph;
pub mod hippocampus;
pub mod operad;

pub use hypergraph::{CognitiveHyperGraph, SuperHyperEdge, MetaRelation};
pub use hippocampus::{HippocampalMemory, CognitiveVector};
pub use operad::{Operad, NeuroUnit, Signal};
