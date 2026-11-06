//! Minimal agent identity, position, and owned skill registry.

use crate::skills::SkillRegistry;
use asfa_kernel::cognitive::CognitiveVector;

pub struct Agent {
    id: String,
    cognitive_position: CognitiveVector,
    skills: SkillRegistry,
}

impl Agent {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            cognitive_position: CognitiveVector::default(),
            skills: SkillRegistry::new(),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn cognitive_position(&self) -> CognitiveVector {
        self.cognitive_position
    }

    pub fn set_cognitive_position(&mut self, position: CognitiveVector) {
        self.cognitive_position = position;
    }

    pub fn skills(&self) -> &SkillRegistry {
        &self.skills
    }

    pub fn skills_mut(&mut self) -> &mut SkillRegistry {
        &mut self.skills
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_owns_mutable_skills_and_position() {
        let mut agent = Agent::new("agent-a");
        agent.set_cognitive_position(CognitiveVector::new(1.0, 2.0, 3.0));
        assert_eq!(agent.id(), "agent-a");
        assert_eq!(
            agent.cognitive_position(),
            CognitiveVector::new(1.0, 2.0, 3.0)
        );
        assert_eq!(agent.skills().len(), 0);
    }
}
