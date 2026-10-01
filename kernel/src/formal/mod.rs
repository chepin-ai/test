//! 形式化验证层

pub struct FormalVerifier;

impl FormalVerifier {
    pub const fn new() -> Self {
        Self
    }

    pub fn load_axioms(&self) {
        // 加载形式化公理
    }
}

pub struct LinearResource<T> {
    value: Option<T>,
    consumed: bool,
}

impl<T> LinearResource<T> {
    pub fn new(value: T) -> Self {
        Self {
            value: Some(value),
            consumed: false,
        }
    }

    pub fn consume<F, R>(mut self, f: F) -> R
    where
        F: FnOnce(T) -> R,
    {
        self.consumed = true;
        let val = self.value.take().unwrap();
        f(val)
    }
}

impl<T> Drop for LinearResource<T> {
    fn drop(&mut self) {
        if !self.consumed && self.value.is_some() {
            panic!("Linear resource dropped without consumption!");
        }
    }
}
