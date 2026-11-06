//! Userspace agent and skill primitives.

#![forbid(unsafe_code)]

pub mod agent;
pub mod skills;

pub use agent::Agent;
pub use skills::{SkillError, SkillRegistry};
