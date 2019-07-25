//#[deny(missing_docs)]
#![doc(include = "../docs/r1cs-docs-example.md")]

#[doc(include = "../docs/cs-proof.md")]
mod notes {}

mod constraint_system;
mod linear_combination;
mod proof;
mod prover;
mod r1cs_utils;
mod verifier;

pub use self::constraint_system::{
    ConstraintSystem, RandomizableConstraintSystem, RandomizedConstraintSystem,
};
pub use self::linear_combination::{LinearCombination, Variable};
pub use self::proof::R1CSProof;
pub use self::prover::Prover;
pub use self::r1cs_utils::{constrain_lc_with_scalar, AllocatedScalar, AllocatedQuantity};
pub use self::verifier::Verifier;
pub use errors::R1CSError;
