#![allow(non_snake_case)]
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate serde;
extern crate serde_json;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::fs;
//use serde;

pub fn two_shuffle<CS: ConstraintSystem>(
    cs: &mut CS,
    A: Variable,
    B: Variable,
    C: Variable,
    D: Variable,
    x: Variable,
) -> Result<(), R1CSError> {
    
        
        let (_, _, l1) = cs.multiply(A.into(), x.into());
        let (_, _, r1) = cs.multiply(B.into(), (Variable::One()-x).into());

        cs.constrain(C - l1 - r1);

        let (_, _, l2) = cs.multiply(B.into(), x.into());
        let (_, _, r2) = cs.multiply(A.into(), (Variable::One()-x).into());

        cs.constrain(D - l2 - r2);

        let (_, _, k) = cs.multiply(x.into(), (Variable::One()-x).into());
        cs.constrain(k - Variable::One() + Variable::One());

        Ok(())
    
}

pub fn prove(
    A: Scalar,
    B: Scalar,
    C: Scalar,
    D: Scalar,
    x: Scalar,
) -> Result<
    (
        R1CSProof,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
    ),
    R1CSError,
> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut prover_transcript = Transcript::new(b"ShuffleTest");
    // Make a prover instance
    let mut prover = Prover::new( &pc_gens, &mut prover_transcript);

    // Create commitments and allocate high-level variables for A, B, C, D, x
    let mut rng = rand::thread_rng();
    let (A_com, A_var) = prover.commit(A, Scalar::random(&mut rng));
    let (B_com, B_var) = prover.commit(B, Scalar::random(&mut rng));
    let (C_com, C_var) = prover.commit(C, Scalar::random(&mut rng));
    let (D_com, D_var) = prover.commit(D, Scalar::random(&mut rng));
    let (x_com, x_var) = prover.commit(x, Scalar::random(&mut rng));

    // Add 2-shuffle gadget constraints to the prover's constraint system
    two_shuffle(&mut prover, A_var, B_var, C_var, D_var, x_var)?;
    // Create a proof
    let proof = prover.prove(&bp_gens)?;

    Ok((proof, A_com, B_com, C_com, D_com, x_com))
}

pub fn verify(
    proof: R1CSProof,
    A_com: CompressedRistretto,
    B_com: CompressedRistretto,
    C_com: CompressedRistretto,
    D_com: CompressedRistretto,
    x_com: CompressedRistretto,
) -> Result<(), R1CSError> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut verifier_transcript = Transcript::new(b"ShuffleTest");
    // Make a verifier instance
    let mut verifier = Verifier::new( &mut verifier_transcript);

    // Allocate high-level variables for A, B, C, D from commitments
    let A_var = verifier.commit(A_com);
    let B_var = verifier.commit(B_com);
    let C_var = verifier.commit(C_com);
    let D_var = verifier.commit(D_com);
    let x_var = verifier.commit(x_com);

    // Add 2-shuffle gadget constraints to the verifier's constraint system
    two_shuffle(&mut verifier, A_var, B_var, C_var, D_var, x_var)?;
    // Verify the proof
    Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_shuffle_without_randomness_verify() {
        println!("{:?}", two_shuffle_helper(3, 6, 3, 6, 1).err());
        assert!(two_shuffle_helper(3, 6, 3, 6, 1).is_ok());
        assert!(two_shuffle_helper(3, 6, 6, 3, 0).is_ok());
        assert!(two_shuffle_helper(6, 6, 6, 6, 1).is_ok());
        assert!(two_shuffle_helper(3, 3, 6, 3, 1).is_err());
    }

    fn two_shuffle_helper(A: u64, B: u64, C: u64, D: u64, x: u64) -> Result<(), R1CSError> {
        //let (proof, A_com, B_com, C_com, D_com, x_com) = prove(A.into(), B.into(), C.into(), D.into(), x.into() )?;
        
        //let proof_str = fs::read_to_string("/tmp/proof").expect("Unable to read file");
        //let proof = serde_json::from_str(&proof_str).unwrap();

        let A_read_bytes = fs::read("/tmp/A_com.bytes").expect("Unable to read file");
        let A_com: CompressedRistretto;
        let A_com = CompressedRistretto::from_slice(&A_read_bytes);

        let B_read_bytes = fs::read("/tmp/B_com.bytes").expect("Unable to read file");
        let B_com: CompressedRistretto;
        let B_com = CompressedRistretto::from_slice(&B_read_bytes);

        let C_read_bytes = fs::read("/tmp/C_com.bytes").expect("Unable to read file");
        let C_com: CompressedRistretto;
        let C_com = CompressedRistretto::from_slice(&C_read_bytes);

        let D_read_bytes = fs::read("/tmp/D_com.bytes").expect("Unable to read file");
        let D_com: CompressedRistretto;
        let D_com = CompressedRistretto::from_slice(&D_read_bytes);

        let x_read_bytes = fs::read("/tmp/x_com.bytes").expect("Unable to read file");
        let x_com: CompressedRistretto;
        let x_com = CompressedRistretto::from_slice(&x_read_bytes);



        let proof_read_bytes = fs::read("/tmp/proof-bytes").expect("Unable to read file");
        println!("verify - Byte Size = {}", proof_read_bytes.len());
        let proof: R1CSProof;
        let proof = R1CSProof::from_bytes(&proof_read_bytes).unwrap();

        verify(proof, A_com, B_com, C_com, D_com, x_com)
    }
}