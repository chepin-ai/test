//! Operads/Monoids - 组合神经科学实现

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::collections::HashMap;

pub trait Operad {
    type Input;
    type Output;

    fn apply(&self, inputs: Vec<Self::Input>) -> Self::Output;
    fn arity(&self) -> usize;
}

pub struct ComposedOperad<A, B> {
    first: A,
    second: B,
}

impl<A, B> Operad for ComposedOperad<A, B> 
where 
    A: Operad,
    B: Operad<Input=A::Output>,
{
    type Input = A::Input;
    type Output = B::Output;

    fn apply(&self, inputs: Vec<Self::Input>) -> Self::Output {
        let intermediate = self.first.apply(inputs);
        self.second.apply(vec![intermediate])
    }

    fn arity(&self) -> usize {
        self.first.arity()
    }
}

pub struct NeuroUnit<I, O> {
    dendrites: Vec<Box<dyn Operad<Input=I, Output=Signal>>>,
    soma: Box<dyn Fn(Vec<Signal>) -> O>,
    threshold: f64,
}

pub struct Signal(pub f64);

impl<I: Clone, O> Operad for NeuroUnit<I, O> {
    type Input = I;
    type Output = O;

    fn apply(&self, inputs: Vec<I>) -> O {
        let signals: Vec<Signal> = self.dendrites.iter()
            .map(|d| d.apply(inputs.clone()))
            .collect();
        (self.soma)(signals)
    }

    fn arity(&self) -> usize {
        1
    }
}

pub struct OperadEngine;

impl OperadEngine {
    pub const fn new() -> Self {
        Self
    }
}
