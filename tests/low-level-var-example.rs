#![allow(non_snake_case)]
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;

// Shuffle gadget (documented in markdown file)

/// A proof-of-shuffle.
struct ShuffleProof(R1CSProof);


/// Constrains (a1 + a2) * (b1 + b2) = (c1 + c2)
fn example_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    a1_var: Option<u64>,
    a2_var: Option<u64>,
    b1_var: Option<u64>,
    b2_var: Option<u64>,
    c1_var: Option<u64>,
    c2_var: Option<u64>,
) {
    // let (_, _, low_var) = cs.allocate_multiplier(prover_low_var.map(|num| {(num.into(), num.into())})).unwrap();
    // let low_var_val = cs.allocate(Some(Scalar::from(16u64))).unwrap();
    // cs.constrain(low_var - low_var_val);

    // let (sVar1) = cs.allocate(Some(s)).unwrap();
    // let (sVar2) = cs.allocate(Some(s)).unwrap();
    
    // cs.constrain(sVar1 - sVar2 );
     let (a1) = cs.allocate(a1_var.map(|num| num.into())).unwrap();
     let (a2) = cs.allocate(a2_var.map(|num| num.into())).unwrap();
     let (b1) = cs.allocate(b1_var.map(|num| num.into())).unwrap();
     let (b2) = cs.allocate(b2_var.map(|num| num.into())).unwrap();
     let (c1) = cs.allocate(c1_var.map(|num| num.into())).unwrap();
     let (c2) = cs.allocate(c2_var.map(|num| num.into())).unwrap();

    cs.constrain(c1.clone() + c2.clone() - Scalar::from(49u32) );
    let (_, _, c_var) = cs.multiply(a1 + a2, b1 + b2);
    cs.constrain(c1 + c2 - c_var);
}

// Prover's scope
fn example_gadget_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(R1CSProof), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high-level variables
    // let (commitments, vars): (Vec<_>, Vec<_>) = [a1, a2, b1, b2]
    //     .into_iter()
    //     .map(|x| prover.commit(Scalar::from(*x), Scalar::random(&mut thread_rng())))
    //     .unzip();

    // 3. Build a CS
    example_gadget(
        &mut prover,
        Some(a1),
        Some(a2),
        Some(b1),
        Some(b2),
        Some(c1),
        Some(c2),
    );

    // 4. Make a proof
    let proof = prover.prove(bp_gens)?;

    Ok((proof))
}

// Verifier logic
fn example_gadget_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    c1: u64,
    c2: u64,
    proof: R1CSProof,
    //commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // 1. Create a verifier
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    // let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();
    // println!("vars[0] = {:?}", vars[0]);
    // 3. Build a CS
    example_gadget(
        &mut verifier,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    // 4. Verify the proof
    verifier
        .verify(&proof, &pc_gens, &bp_gens)
        .map_err(|_| R1CSError::VerificationError)
}

fn example_gadget_roundtrip_helper(
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

    example_gadget_verify(&pc_gens, &bp_gens, c1, c2, proof)
}

fn example_gadget_roundtrip_serialization_helper(
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

    let proof = proof.to_bytes();

    let proof = R1CSProof::from_bytes(&proof)?;

    example_gadget_verify(&pc_gens, &bp_gens, c1, c2, proof)
}

#[test]
fn example_gadget_test_add_low_level_vars() {
    // (3 + 4) * (6 + 1) = (40 + 9)
    println!("{:?}", example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 9).err());
    //assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 9).is_ok());
    // (3 + 4) * (6 + 1) != (40 + 10)
    assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 10).is_err());
}

// #[test]
// fn example_gadget_serialization_test() {
//     // (3 + 4) * (6 + 1) = (40 + 9)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 9).is_ok());
//     // (3 + 4) * (6 + 1) != (40 + 10)
//     assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 10).is_err());
// }
