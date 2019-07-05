#![allow(non_snake_case)]
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;
extern crate bigint;

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use bigint::uint::U256;

pub fn big_int_experiment<CS: RandomizableConstraintSystem>(
    cs: &mut CS,
    A: Variable,
    B: Variable,
    C: Variable,
    D: Variable,
) -> Result<(), R1CSError> {
    cs.specify_randomized_constraints(move |cs| {
        // Get challenge scalar x
        let x = cs.challenge_scalar(b"big_int challenge");
        // (A - x)*(B - x) = input_mul
        let (_, _, input_mul) = cs.multiply(A - x, B - x);
        // (C - x)*(D - x) = output_mul
        let (_, _, output_mul) = cs.multiply(C - x, D - x);
        // input_mul - output_mul = 0
        cs.constrain(input_mul - output_mul);

        Ok(())
    })
}

pub fn prove(
    A: Scalar,
    B: Scalar,
    C: Scalar,
    D: Scalar,
) -> Result<
    (
        R1CSProof,
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
    let mut prover_transcript = Transcript::new(b"big_intTest");
    // Make a prover instance
    let mut prover = Prover::new( &pc_gens, &mut prover_transcript);

    // Create commitments and allocate high-level variables for A, B, C, D
    let mut rng = rand::thread_rng();
    let (A_com, A_var) = prover.commit(A, Scalar::random(&mut rng));
    let (B_com, B_var) = prover.commit(B, Scalar::random(&mut rng));
    let (C_com, C_var) = prover.commit(C, Scalar::random(&mut rng));
    let (D_com, D_var) = prover.commit(D, Scalar::random(&mut rng));

    // Add 2-big_int gadget constraints to the prover's constraint system
    big_int_experiment(&mut prover, A_var, B_var, C_var, D_var)?;
    // Create a proof
    let proof = prover.prove(&bp_gens)?;

    Ok((proof, A_com, B_com, C_com, D_com))
}

pub fn verify(
    proof: R1CSProof,
    A_com: CompressedRistretto,
    B_com: CompressedRistretto,
    C_com: CompressedRistretto,
    D_com: CompressedRistretto,
) -> Result<(), R1CSError> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut verifier_transcript = Transcript::new(b"big_intTest");
    // Make a verifier instance
    let mut verifier = Verifier::new( &mut verifier_transcript);

    // Allocate high-level variables for A, B, C, D from commitments
    let A_var = verifier.commit(A_com);
    let B_var = verifier.commit(B_com);
    let C_var = verifier.commit(C_com);
    let D_var = verifier.commit(D_com);

    // Add 2-big_int gadget constraints to the verifier's constraint system
    big_int_experiment(&mut verifier, A_var, B_var, C_var, D_var)?;
    // Verify the proof
    Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn big_int_experiment() {
        assert!(big_int_experiment_helper(3, 6, 3, 6).is_ok());
        //assert!(big_int_experiment_helper(3, 6, 6, 3).is_ok());
        //assert!(big_int_experiment_helper(6, 6, 6, 6).is_ok());
        //assert!(big_int_experiment_helper(3, 3, 6, 3).is_err());
    }

    fn big_int_experiment_helper(A: u64, B: u64, C: u64, D: u64) -> Result<(), R1CSError> {
        
        let str_s : String = "100".to_string();
        let A1 = bigint::uint::U256::from_dec_str(&str_s);
        let str_to_num = str_s.parse::<u32>().unwrap();
        println!("string_to_num = {:}", str_to_num);
        let mut a = [0u8;32];
        let A2 = A1.unwrap().to_little_endian(&mut a);
        println!("{:?}", a);
        println!("-----");
        let K1 = Scalar::from_bits(a);
        println!(" K1 {:?}", K1.to_bytes());
        let K2 = -K1;
        println!(" K2 {:?}", K2.to_bytes());
        let K3 = -K2;
        println!(" K3 {:?}", K3.to_bytes());
//

      //  let a1 = bigint::uint::U256::from_dec_str("1000000000000000000000000000000000000000000").unwrap().to_little_endian(&mut a);


     //let (proof, A_com, B_com, C_com, D_com) = prove(A.into(), B.into(), C.into(), D.into())?;
         let (proof, A_com, B_com, C_com, D_com) = prove(K1, B.into(), K1, D.into())?;
        verify(proof, A_com, B_com, C_com, D_com)
    }
}