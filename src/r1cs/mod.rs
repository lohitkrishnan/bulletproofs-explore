//#[deny(missing_docs)]
#![doc(include = "../docs/r1cs-docs-example.md")]

#[doc(include = "../docs/cs-proof.md")]
mod notes {}

mod constraint_system;
mod linear_combination;
mod proof;
mod prover;
mod verifier;
mod r1cs_utils;

pub use self::constraint_system::{
    ConstraintSystem, RandomizableConstraintSystem, RandomizedConstraintSystem,
};
pub use self::linear_combination::{LinearCombination, Variable};
pub use self::proof::R1CSProof;
pub use self::prover::Prover;
pub use self::verifier::Verifier;
pub use self::r1cs_utils::{AllocatedScalar, constrain_lc_with_scalar};
pub use errors::R1CSError;
