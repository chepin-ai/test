//! SuperHyperGraph 实现 - 高阶认知关系
//! 基于 "Cognitive HyperGraphs and SuperHyperGraphs"

use alloc::collections::{HashMap, HashSet};
use alloc::vec::Vec;
use core::hash::Hash;
use spin::Mutex;

/// 超超边 (SuperHyperEdge): 连接多个超边的高阶关系
pub struct SuperHyperEdge<R, A, S> 
where 
    R: Clone + Hash + Eq,
    A: Clone + Hash + Eq,
    S: Clone + Hash + Eq,
{
    pub resource_edges: Vec<HashSet<R>>,
    pub agent_edges: Vec<HashSet<A>>,
    pub state_edges: Vec<HashSet<S>>,
    pub meta_relation: MetaRelation,
    pub activation: f64,
    pub temporal_marker: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MetaRelation {
    Causal,
    Temporal,
    Analogical,
    Compositional,
    Hierarchical,
}

pub type EdgeId = u64;
pub type VertexId = u64;

/// 认知超图 (线程安全)
pub struct CognitiveHyperGraph<R, A, S> {
    edges: Mutex<HashMap<EdgeId, SuperHyperEdge<R, A, S>>>,
    adjacency: Mutex<HashMap<VertexId, Vec<EdgeId>>>,
    next_id: Mutex<u64>,
}

impl<R, A, S> CognitiveHyperGraph<R, A, S> 
where 
    R: Clone + Hash + Eq + Send,
    A: Clone + Hash + Eq + Send,
    S: Clone + Hash + Eq + Send,
{
    pub const fn new() -> Self {
        Self {
            edges: Mutex::new(HashMap::new()),
            adjacency: Mutex::new(HashMap::new()),
            next_id: Mutex::new(0),
        }
    }

    pub fn create_super_edge(
        &self,
        resources: Vec<HashSet<R>>,
        agents: Vec<HashSet<A>>,
        states: Vec<HashSet<S>>,
        meta: MetaRelation,
    ) -> EdgeId {
        let id = {
            let mut guard = self.next_id.lock();
            let id = *guard;
            *guard += 1;
            id
        };

        let edge = SuperHyperEdge {
            resource_edges: resources,
            agent_edges: agents,
            state_edges: states,
            meta_relation: meta,
            activation: 1.0,
            temporal_marker: 0,
        };

        self.edges.lock().insert(id, edge);
        id
    }

    pub fn pattern_completion(
        &self,
        partial_resources: HashSet<R>,
        partial_agents: HashSet<A>,
    ) -> Vec<EdgeId> {
        let edges = self.edges.lock();
        edges.iter()
            .filter(|(_, edge)| {
                let res_union: HashSet<_> = edge.resource_edges.iter()
                    .flatten().cloned().collect();
                let agent_union: HashSet<_> = edge.agent_edges.iter()
                    .flatten().cloned().collect();
                partial_resources.is_subset(&res_union)
                    && partial_agents.is_subset(&agent_union)
            })
            .map(|(id, _)| *id)
            .collect()
    }
}
