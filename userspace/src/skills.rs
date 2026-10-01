//! Skill 注册表

use alloc::collections::HashMap;

pub struct SkillRegistry {
    skills: HashMap<String, Box<dyn Fn() -> ()>>,
}

impl SkillRegistry {
    pub fn new() -> Self {
        Self {
            skills: HashMap::new(),
        }
    }
}
