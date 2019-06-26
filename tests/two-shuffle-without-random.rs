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

    //fs::write("/tmp/pc_gens.bytes", pc_gens.to_bytes()).expect("Unable to write file - pc_gens ");
    //fs::write("/tmp/bp_gens.bytes", bp_gens.to_bytes()).expect("Unable to write file - bp_gens ");

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
    fn two_shuffle_without_randomness() {
        assert!(two_shuffle_helper(3, 6, 3, 6, 1).is_ok());
        assert!(two_shuffle_helper(3, 6, 6, 3, 0).is_ok());
        assert!(two_shuffle_helper(6, 6, 6, 6, 1).is_ok());
        assert!(two_shuffle_helper(3, 3, 6, 3, 1).is_err());
    }

    fn two_shuffle_helper(A: u64, B: u64, C: u64, D: u64, x: u64) -> Result<(), R1CSError> {
        let (proof, A_com, B_com, C_com, D_com, x_com) = prove(A.into(), B.into(), C.into(), D.into(), x.into() )?;

        fs::write("/tmp/A_com.bytes", A_com.to_bytes()).expect("Unable to write file - A_com");

        fs::write("/tmp/B_com.bytes", B_com.to_bytes()).expect("Unable to write file - B_com");

        fs::write("/tmp/C_com.bytes", C_com.to_bytes()).expect("Unable to write file - C_com");

        fs::write("/tmp/D_com.bytes", D_com.to_bytes()).expect("Unable to write file - D_com");

        fs::write("/tmp/x_com.bytes", x_com.to_bytes()).expect("Unable to write file - x_com");


        //let A_com_str = serde_json::to_string(&A_com).unwrap();
        //fs::write("/tmp/A_com", A_com_str).expect("Unable to write file - A_com");

        // let B_com_str = serde_json::to_string(&B_com).unwrap();
        // fs::write("/tmp/B_com", B_com_str).expect("Unable to write file - B_com");

        // let C_com_str = serde_json::to_string(&C_com).unwrap();
        // fs::write("/tmp/C_com", C_com_str).expect("Unable to write file - C_com");

        // let D_com_str = serde_json::to_string(&D_com).unwrap();
        // fs::write("/tmp/D_com", D_com_str).expect("Unable to write file - D_com");

        // let x_com_str = serde_json::to_string(&x_com).unwrap();
        // fs::write("/tmp/x_com", x_com_str).expect("Unable to write file - x_com");

        

        let bytes_proof = proof.to_bytes();
        fs::write("/tmp/proof-bytes", bytes_proof).expect("Unable to write file - bytes-proof");

        println!("Writing - Proof Size = {}",proof.serialized_size());

        
        let proof_read_bytes = fs::read("/tmp/proof-bytes").expect("Unable to read file");
        let proof1: R1CSProof;
        let proof1 = R1CSProof::from_bytes(&proof_read_bytes).unwrap();
        println!("Reading - Proof Size = {}", proof_read_bytes.len());
        let bytes_proof = proof.to_bytes();
        assert_eq!( proof_read_bytes, bytes_proof);

        let A_read_bytes = fs::read("/tmp/A_com.bytes").expect("Unable to read file");
        let A_com1: CompressedRistretto;
        let A_com1 = CompressedRistretto::from_slice(&A_read_bytes);
        println!("Reading - A Size = {}", A_read_bytes.len());
        let A_com_old_bytes = A_com.to_bytes();
        let B_com_old_bytes = B_com.to_bytes();
        let C_com_old_bytes = C_com.to_bytes();
        let D_com_old_bytes = D_com.to_bytes();
        let x_com_old_bytes = x_com.to_bytes();
        assert_eq!(A_read_bytes, A_com_old_bytes);
        //assert_eq!(1,0);

        let B_read_bytes = fs::read("/tmp/B_com.bytes").expect("Unable to read file");
        let B_com1: CompressedRistretto;
        let B_com1 = CompressedRistretto::from_slice(&B_read_bytes);
        println!("Reading - B Size = {}", B_read_bytes.len());
        assert_eq!(B_read_bytes, B_com_old_bytes);

        let C_read_bytes = fs::read("/tmp/C_com.bytes").expect("Unable to read file");
        let C_com1: CompressedRistretto;
        let C_com1 = CompressedRistretto::from_slice(&C_read_bytes);
        println!("Reading - C Size = {}", C_read_bytes.len());
        assert_eq!(C_read_bytes, C_com_old_bytes);

        let D_read_bytes = fs::read("/tmp/D_com.bytes").expect("Unable to read file");
        let D_com1: CompressedRistretto;
        let D_com1 = CompressedRistretto::from_slice(&D_read_bytes);
        println!("Reading - D Size = {}", D_read_bytes.len());
        assert_eq!(D_read_bytes, D_com_old_bytes);

        let x_read_bytes = fs::read("/tmp/x_com.bytes").expect("Unable to read file");
        let x_com1: CompressedRistretto;
        let x_com1 = CompressedRistretto::from_slice(&x_read_bytes);
        println!("Reading - x Size = {}", x_read_bytes.len());
        assert_eq!(x_read_bytes, x_com_old_bytes);

        verify(proof1, A_com1, B_com1, C_com1, D_com1, x_com1)
    }
}