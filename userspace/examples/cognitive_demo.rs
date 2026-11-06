use asfa_kernel::cognitive::{CognitiveHyperGraph, MetaRelation};
use asfa_userspace::Agent;
use serde_json::json;
use std::collections::HashSet;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut agent = Agent::new("demo-agent");
    agent.skills_mut().register("add", |input| {
        let a = input["a"].as_i64().ok_or_else(|| {
            asfa_userspace::SkillError::ExecutionFailed("a must be integer".into())
        })?;
        let b = input["b"].as_i64().ok_or_else(|| {
            asfa_userspace::SkillError::ExecutionFailed("b must be integer".into())
        })?;
        Ok(json!({"sum": a + b}))
    })?;
    let output = agent.skills().execute("add", json!({"a": 20, "b": 22}))?;

    let graph = CognitiveHyperGraph::new();
    let edge = graph.create_super_edge(
        vec![HashSet::from(["document-a"])],
        vec![HashSet::from([agent.id()])],
        vec![HashSet::from(["validated"])],
        MetaRelation::Compositional,
        1,
    )?;
    let matches =
        graph.pattern_completion(&HashSet::from(["document-a"]), &HashSet::from([agent.id()]))?;
    println!("skill_output={output}; edge={edge}; matches={matches:?}");
    Ok(())
}
