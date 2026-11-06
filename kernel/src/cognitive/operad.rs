//! Checked composition for heterogeneous computational primitives.

use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperadError {
    ArityMismatch { expected: usize, actual: usize },
    CompositionRequiresUnary { actual: usize },
    ExecutionFailed(String),
}

impl Display for OperadError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArityMismatch { expected, actual } => {
                write!(f, "expected {expected} inputs, got {actual}")
            }
            Self::CompositionRequiresUnary { actual } => write!(
                f,
                "composition requires a unary second stage, got arity {actual}"
            ),
            Self::ExecutionFailed(message) => f.write_str(message),
        }
    }
}

impl Error for OperadError {}

pub trait Operad {
    type Input;
    type Output;

    fn arity(&self) -> usize;
    fn apply(&self, inputs: Vec<Self::Input>) -> Result<Self::Output, OperadError>;

    fn compose<B>(self, second: B) -> Result<ComposedOperad<Self, B>, OperadError>
    where
        Self: Sized,
        B: Operad<Input = Self::Output>,
    {
        if second.arity() != 1 {
            return Err(OperadError::CompositionRequiresUnary {
                actual: second.arity(),
            });
        }
        Ok(ComposedOperad {
            first: self,
            second,
        })
    }
}

pub struct ComposedOperad<A, B> {
    first: A,
    second: B,
}

impl<A, B> Operad for ComposedOperad<A, B>
where
    A: Operad,
    B: Operad<Input = A::Output>,
{
    type Input = A::Input;
    type Output = B::Output;

    fn arity(&self) -> usize {
        self.first.arity()
    }

    fn apply(&self, inputs: Vec<Self::Input>) -> Result<Self::Output, OperadError> {
        let intermediate = self.first.apply(inputs)?;
        self.second.apply(vec![intermediate])
    }
}

pub struct FunctionOperad<I, O> {
    arity: usize,
    function: Box<dyn Fn(Vec<I>) -> Result<O, OperadError> + Send + Sync>,
}

impl<I, O> FunctionOperad<I, O> {
    pub fn new<F>(arity: usize, function: F) -> Self
    where
        F: Fn(Vec<I>) -> Result<O, OperadError> + Send + Sync + 'static,
    {
        Self {
            arity,
            function: Box::new(function),
        }
    }
}

impl<I, O> Operad for FunctionOperad<I, O> {
    type Input = I;
    type Output = O;

    fn arity(&self) -> usize {
        self.arity
    }

    fn apply(&self, inputs: Vec<I>) -> Result<O, OperadError> {
        if inputs.len() != self.arity {
            return Err(OperadError::ArityMismatch {
                expected: self.arity,
                actual: inputs.len(),
            });
        }
        (self.function)(inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_executes_both_stages_in_order() {
        let sum = FunctionOperad::new(2, |values: Vec<i32>| Ok(values.into_iter().sum::<i32>()));
        let double = FunctionOperad::new(1, |values: Vec<i32>| Ok(values[0] * 2));
        let pipeline = sum.compose(double).unwrap();
        assert_eq!(pipeline.apply(vec![3, 4]), Ok(14));
    }

    #[test]
    fn wrong_arity_is_rejected_before_execution() {
        let sum = FunctionOperad::new(2, |values: Vec<i32>| Ok(values.into_iter().sum::<i32>()));
        assert_eq!(
            sum.apply(vec![1]),
            Err(OperadError::ArityMismatch {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn non_unary_second_stage_cannot_be_composed() {
        let first = FunctionOperad::new(1, |values: Vec<i32>| Ok(values[0]));
        let second = FunctionOperad::new(2, |values: Vec<i32>| Ok(values.into_iter().sum::<i32>()));
        assert_eq!(
            first.compose(second).err(),
            Some(OperadError::CompositionRequiresUnary { actual: 2 })
        );
    }

    #[test]
    fn execution_errors_are_not_silently_skipped() {
        let failing = FunctionOperad::new(1, |_values: Vec<i32>| {
            Err::<i32, _>(OperadError::ExecutionFailed("boom".into()))
        });
        assert_eq!(
            failing.apply(vec![1]),
            Err(OperadError::ExecutionFailed("boom".into()))
        );
    }
}
