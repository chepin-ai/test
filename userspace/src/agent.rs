//! Agent 抽象

pub struct Agent {
    id: String,
    cognitive_position: (f64, f64, f64),
}

impl Agent {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            cognitive_position: (0.0, 0.0, 0.0),
        }
    }
}
