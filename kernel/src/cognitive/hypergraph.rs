//! Deterministic n-ary relation storage and subset retrieval.

use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

pub type EdgeId = u64;

/// A relation among non-empty resource, agent, and state sets.
#[derive(Clone, Debug, PartialEq)]
pub struct SuperHyperEdge<R, A, S>
where
    R: Clone + Eq + Hash,
    A: Clone + Eq + Hash,
    S: Clone + Eq + Hash,
{
    pub resource_edges: Vec<HashSet<R>>,
    pub agent_edges: Vec<HashSet<A>>,
    pub state_edges: Vec<HashSet<S>>,
    pub meta_relation: MetaRelation,
    pub activation: f64,
    pub temporal_marker: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetaRelation {
    Causal,
    Temporal,
    Analogical,
    Compositional,
    Hierarchical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HyperGraphError {
    EmptyDimension(&'static str),
    LockPoisoned,
}

impl Display for HyperGraphError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyDimension(name) => write!(f, "{name} must contain at least one set"),
            Self::LockPoisoned => f.write_str("hypergraph lock is poisoned"),
        }
    }
}

impl Error for HyperGraphError {}

/// Thread-safe hypergraph. Edge IDs are stable and start at 1.
pub struct CognitiveHyperGraph<R, A, S>
where
    R: Clone + Eq + Hash,
    A: Clone + Eq + Hash,
    S: Clone + Eq + Hash,
{
    edges: RwLock<BTreeMap<EdgeId, SuperHyperEdge<R, A, S>>>,
    next_id: AtomicU64,
}

impl<R, A, S> Default for CognitiveHyperGraph<R, A, S>
where
    R: Clone + Eq + Hash,
    A: Clone + Eq + Hash,
    S: Clone + Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R, A, S> CognitiveHyperGraph<R, A, S>
where
    R: Clone + Eq + Hash,
    A: Clone + Eq + Hash,
    S: Clone + Eq + Hash,
{
    pub fn new() -> Self {
        Self {
            edges: RwLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn create_super_edge(
        &self,
        resources: Vec<HashSet<R>>,
        agents: Vec<HashSet<A>>,
        states: Vec<HashSet<S>>,
        meta_relation: MetaRelation,
        temporal_marker: u64,
    ) -> Result<EdgeId, HyperGraphError> {
        if resources.is_empty() {
            return Err(HyperGraphError::EmptyDimension("resources"));
        }
        if agents.is_empty() {
            return Err(HyperGraphError::EmptyDimension("agents"));
        }
        if states.is_empty() {
            return Err(HyperGraphError::EmptyDimension("states"));
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let edge = SuperHyperEdge {
            resource_edges: resources,
            agent_edges: agents,
            state_edges: states,
            meta_relation,
            activation: 1.0,
            temporal_marker,
        };
        self.edges
            .write()
            .map_err(|_| HyperGraphError::LockPoisoned)?
            .insert(id, edge);
        Ok(id)
    }

    pub fn edge(&self, id: EdgeId) -> Result<Option<SuperHyperEdge<R, A, S>>, HyperGraphError> {
        Ok(self
            .edges
            .read()
            .map_err(|_| HyperGraphError::LockPoisoned)?
            .get(&id)
            .cloned())
    }

    pub fn len(&self) -> Result<usize, HyperGraphError> {
        Ok(self
            .edges
            .read()
            .map_err(|_| HyperGraphError::LockPoisoned)?
            .len())
    }

    pub fn is_empty(&self) -> Result<bool, HyperGraphError> {
        Ok(self.len()? == 0)
    }

    /// Return IDs whose resource and agent unions contain both partial sets.
    /// Empty queries match every edge, which is explicit subset semantics.
    pub fn pattern_completion(
        &self,
        partial_resources: &HashSet<R>,
        partial_agents: &HashSet<A>,
    ) -> Result<Vec<EdgeId>, HyperGraphError> {
        let edges = self
            .edges
            .read()
            .map_err(|_| HyperGraphError::LockPoisoned)?;
        let mut matches = Vec::new();
        for (id, edge) in edges.iter() {
            let resources: HashSet<&R> = edge.resource_edges.iter().flatten().collect();
            let agents: HashSet<&A> = edge.agent_edges.iter().flatten().collect();
            if partial_resources
                .iter()
                .all(|item| resources.contains(item))
                && partial_agents.iter().all(|item| agents.contains(item))
            {
                matches.push(*id);
            }
        }
        Ok(matches)
    }

    /// Find same-relation edges sharing at least one agent with the start edge.
    pub fn linked_by_shared_agents(
        &self,
        start: EdgeId,
        relation: MetaRelation,
    ) -> Result<Vec<EdgeId>, HyperGraphError> {
        let edges = self
            .edges
            .read()
            .map_err(|_| HyperGraphError::LockPoisoned)?;
        let start_edge = edges
            .get(&start)
            .ok_or(HyperGraphError::EmptyDimension("start edge"))?;
        let start_agents: HashSet<&A> = start_edge.agent_edges.iter().flatten().collect();

        Ok(edges
            .iter()
            .filter(|(id, edge)| {
                **id != start
                    && edge.meta_relation == relation
                    && edge
                        .agent_edges
                        .iter()
                        .flatten()
                        .any(|agent| start_agents.contains(agent))
            })
            .map(|(id, _)| *id)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn edge<'a>(
        graph: &CognitiveHyperGraph<&'a str, &'a str, &'a str>,
        r: &'a str,
        a: &'a str,
        s: &'a str,
    ) -> EdgeId {
        graph
            .create_super_edge(
                vec![HashSet::from([r])],
                vec![HashSet::from([a])],
                vec![HashSet::from([s])],
                MetaRelation::Causal,
                7,
            )
            .unwrap()
    }

    #[test]
    fn rejects_empty_dimensions() {
        let graph = CognitiveHyperGraph::<&str, &str, &str>::new();
        let error = graph
            .create_super_edge(
                vec![],
                vec![HashSet::from(["a"])],
                vec![HashSet::from(["s"])],
                MetaRelation::Causal,
                0,
            )
            .unwrap_err();
        assert_eq!(error, HyperGraphError::EmptyDimension("resources"));
    }

    #[test]
    fn completion_is_deterministic_and_subset_based() {
        let graph = CognitiveHyperGraph::new();
        let first = edge(&graph, "r1", "a1", "s1");
        let second = edge(&graph, "r2", "a2", "s2");
        assert_eq!(
            graph
                .pattern_completion(&HashSet::from(["r1"]), &HashSet::new())
                .unwrap(),
            vec![first]
        );
        assert_eq!(
            graph
                .pattern_completion(&HashSet::new(), &HashSet::new())
                .unwrap(),
            vec![first, second]
        );
        assert!(graph
            .pattern_completion(&HashSet::from(["missing"]), &HashSet::new())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn traversal_requires_relation_and_shared_agent() {
        let graph = CognitiveHyperGraph::new();
        let first = edge(&graph, "r1", "shared", "s1");
        let second = edge(&graph, "r2", "shared", "s2");
        let _third = edge(&graph, "r3", "other", "s3");
        assert_eq!(
            graph
                .linked_by_shared_agents(first, MetaRelation::Causal)
                .unwrap(),
            vec![second]
        );
    }

    #[test]
    fn concurrent_creation_never_reuses_ids() {
        let graph = Arc::new(CognitiveHyperGraph::new());
        let mut workers = Vec::new();
        for worker in 0..8 {
            let graph = Arc::clone(&graph);
            workers.push(std::thread::spawn(move || {
                for item in 0..32 {
                    let resource = Box::leak(format!("r-{worker}-{item}").into_boxed_str());
                    edge(&graph, resource, "agent", "state");
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(graph.len().unwrap(), 256);
        let ids = graph
            .pattern_completion(&HashSet::new(), &HashSet::new())
            .unwrap();
        let unique: HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 256);
    }
}
