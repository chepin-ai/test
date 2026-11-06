//! Named JSON skills with explicit registration and execution errors.

use serde_json::Value;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

pub type SkillResult = Result<Value, SkillError>;
pub type SkillHandler = Box<dyn Fn(Value) -> SkillResult + Send + Sync>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillError {
    InvalidName,
    UnknownSkill(String),
    ExecutionFailed(String),
}

impl Display for SkillError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName => f.write_str("skill name must not be empty"),
            Self::UnknownSkill(name) => write!(f, "unknown skill: {name}"),
            Self::ExecutionFailed(message) => f.write_str(message),
        }
    }
}

impl Error for SkillError {}

pub struct SkillRegistry {
    skills: BTreeMap<String, SkillHandler>,
}

impl Default for SkillRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SkillRegistry {
    pub fn new() -> Self {
        Self {
            skills: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.skills.len()
    }

    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    pub fn names(&self) -> Vec<&str> {
        self.skills.keys().map(String::as_str).collect()
    }

    pub fn register<F>(&mut self, name: impl Into<String>, handler: F) -> Result<(), SkillError>
    where
        F: Fn(Value) -> SkillResult + Send + Sync + 'static,
    {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(SkillError::InvalidName);
        }
        self.skills.insert(name, Box::new(handler));
        Ok(())
    }

    pub fn execute(&self, name: &str, input: Value) -> SkillResult {
        let handler = self
            .skills
            .get(name)
            .ok_or_else(|| SkillError::UnknownSkill(name.into()))?;
        handler(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registered_skill_executes_real_handler() {
        let mut registry = SkillRegistry::new();
        registry
            .register("add", |input| {
                let a = input["a"]
                    .as_i64()
                    .ok_or_else(|| SkillError::ExecutionFailed("a must be integer".into()))?;
                let b = input["b"]
                    .as_i64()
                    .ok_or_else(|| SkillError::ExecutionFailed("b must be integer".into()))?;
                Ok(json!({"sum": a + b}))
            })
            .unwrap();
        assert_eq!(
            registry.execute("add", json!({"a": 2, "b": 5})).unwrap(),
            json!({"sum": 7})
        );
        assert_eq!(registry.names(), vec!["add"]);
    }

    #[test]
    fn unknown_and_invalid_skills_fail_loudly() {
        let registry = SkillRegistry::new();
        assert_eq!(
            registry.execute("missing", json!({})),
            Err(SkillError::UnknownSkill("missing".into()))
        );
        let mut registry = SkillRegistry::new();
        assert_eq!(
            registry.register(" ", |_input| Ok(json!(null))),
            Err(SkillError::InvalidName)
        );
    }
}
