#![allow(non_snake_case)]
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate serde;
extern crate serde_json;
extern crate bincode;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::fs;
use bincode::serialize_into;
use std::io::BufWriter;
use std::io::BufReader;
use std::fs::File;
//use serde;

pub fn two_variable_read<CS: ConstraintSystem>(
    cs: &mut CS,
    A: Variable,
    B: Variable,
) -> Result<(), R1CSError> {
    
        cs.constrain(A - B);

        Ok(())
    
}

pub fn prove(
    A: Scalar,
    B: Scalar,
) -> Result<
    (
        R1CSProof,
        CompressedRistretto,
        CompressedRistretto,
    ),
    R1CSError,
> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let mut prover_transcript = Transcript::new(b"TwoVariableTest");
    // Make a prover instance
    let mut prover = Prover::new( &pc_gens, &mut prover_transcript);

    // Create commitments and allocate high-level variables for A, B
    let mut rng = rand::thread_rng();
    let (A_com, A_var) = prover.commit(A, Scalar::random(&mut rng));
    let (B_com, B_var) = prover.commit(B, Scalar::random(&mut rng));
    
    // Add 2-shuffle gadget constraints to the prover's constraint system
    two_variable_read(&mut prover, A_var, B_var)?;
    // Create a proof
    let proof = prover.prove(&bp_gens)?;

    Ok((proof, A_com, B_com))
}

pub fn verify(
    proof: R1CSProof,
    A_com: CompressedRistretto,
    B_com: CompressedRistretto,
) -> Result<(), R1CSError> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut verifier_transcript = Transcript::new(b"TwoVariableTest");
    // Make a verifier instance
    let mut verifier = Verifier::new( &mut verifier_transcript);

    // Allocate high-level variables for A, B, from commitments
    let A_var = verifier.commit(A_com);
    let B_var = verifier.commit(B_com);

    // Add 2-shuffle gadget constraints to the verifier's constraint system
    two_variable_read(&mut verifier, A_var, B_var)?;
    // Verify the proof
    Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_variable_read() {
        //assert!(two_variable_read_helper().is_ok());
        
        //The following line prints "Some(VerificationError)"
        println!("{:?}", two_variable_read_helper().err());
       
    }

    fn two_variable_read_helper() -> Result<(), R1CSError> {
        
       //Reading Proof from file
        let proof_read_bytes = fs::read("/tmp/proof-bytes").expect("Unable to read file");
        let proof1: R1CSProof;
        let proof1 = R1CSProof::from_bytes(&proof_read_bytes).unwrap();
        println!("Reading - Proof Size = {}", proof_read_bytes.len());

        //Reading A-Commitment
        let A_read_bytes = fs::read("/tmp/A_com.bytes").expect("Unable to read file");
        let A_com1: CompressedRistretto;
        let A_com1 = CompressedRistretto::from_slice(&A_read_bytes);
        println!("Reading - A Size = {}", A_read_bytes.len());

        //Reading B-Commitment
        let B_read_bytes = fs::read("/tmp/B_com.bytes").expect("Unable to read file");
        let B_com1: CompressedRistretto;
        let B_com1 = CompressedRistretto::from_slice(&B_read_bytes);
        println!("Reading - B Size = {}", B_read_bytes.len());

        //Running verify with the read values. 
        //This throws error - VerificationError!
        verify(proof1, A_com1, B_com1)
    }
}