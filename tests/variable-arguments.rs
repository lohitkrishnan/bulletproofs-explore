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
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::error::Error;

pub fn getEquation(
    //cs: &mut <Type as bulletproofs::r1cs::RandomizableConstraintSystem>::RandomizedCS,
    varArr : & Vec<Variable>,
    circuitConfigArr : &Vec<i32>,
    mut i :  usize,
) -> LinearCombination {

     let mut a : LinearCombination = LinearCombination::default();
        let mut n_terms = circuitConfigArr[i];
        i = i  + 1;
        let mut term_cnt = 0;
        while term_cnt < n_terms {
            //i = i + 2;
            let mut varNum  = circuitConfigArr[i];
            let mut coeff = circuitConfigArr[i+1] ;
            if coeff < 0 {
                coeff = coeff * -1;
                a  =  a - Scalar::from(coeff as u32)*varArr[varNum as usize];
            } else {
                a  =  a + Scalar::from(coeff as u32)*varArr[varNum as usize];  
            }
            
            i = i + 2;
            term_cnt = term_cnt + 1;
        }
    return a;
}

pub fn variable_argument<CS: ConstraintSystem>(
    cs: &mut CS,
    varArr : & Vec<Variable>,
    arrLen : usize,
    circuitConfigArr : &Vec<i32>,
) -> Result<(), R1CSError> {
    //cs.specify_randomized_constraints(move |cs| {
        // Get challenge scalar x
        //let x = cs.challenge_scalar(b"shuffle challenge");
        // (A - x)*(B - x) = input_mul

    /*
    for i in 0..2 {
        let (_, _, input_mul) = cs.multiply(Scalar::one()*varArr[i], Scalar::one()*varArr[i+1]);
        // (C - x)*(D - x) = output_mul
        let (_, _, output_mul) = cs.multiply(varArr[i+2].into(), Scalar::one().into());
        // input_mul - output_mul = 0
        cs.constrain(input_mul - output_mul);
    }
    */

    let mut i : usize = 0;

    while i < circuitConfigArr.len() {
        println!("before a - {}",i);
        let mut a = getEquation( varArr, circuitConfigArr, i);
        println!("before a - {}",i);
        i = i + (circuitConfigArr[i] as usize)*2  + 1;
        println!("after a - {}",i);
        let mut b = getEquation( varArr, circuitConfigArr,i);
        println!("after a - {}",i);
        i = i + (circuitConfigArr[i] as usize)*2  + 1;
        println!("after b - {}",i);
        let mut c = getEquation( varArr, circuitConfigArr,i);
        println!("after b - {}",i);
        i = i + (circuitConfigArr[i] as usize)*2  + 1;
        println!("after c - {}",i);

       let (_, _, lhs) = cs.multiply(a, b);
        // (C - x)*(D - x) = output_mul
        let (_, _, rhs) = cs.multiply(c, Scalar::one().into());
        // input_mul - output_mul = 0
        cs.constrain(lhs - rhs);
    }

/*
        let (_, _, input_mul) = cs.multiply(Scalar::from(2u64)*varArr[0] - Scalar::from(3u64)*varArr[1], Scalar::from(2u64)*varArr[2]);
        // (C - x)*(D - x) = output_mul
        let (_, _, output_mul) = cs.multiply(varArr[2].into(), varArr[3].into());
        // input_mul - output_mul = 0
        cs.constrain(input_mul - output_mul);
*/
        Ok(())
   // })
}

pub fn prove(
    rawVar: &[u32],
    circuitConfigArr : &Vec<i32>,
) -> Result<
    (
        R1CSProof,
        Vec<CompressedRistretto>,
    ),
    R1CSError,
> {
    let A : Vec<Scalar> = rawVar.iter().map(|&x| x.into()).collect();
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut prover_transcript = Transcript::new(b"ShuffleTest");
    // Make a prover instance
    let mut prover = Prover::new( &pc_gens, &mut prover_transcript);

    // Create commitments and allocate high-level variables for A, B, C, D
    let mut rng = rand::thread_rng();
    
    let mut comArr : Vec<CompressedRistretto> = Vec::new();
    let mut varArr : Vec<Variable> = Vec::new();

    for idx in 0..A.len() {
        //println!("idx = {:}", idx);
        let (curCom, curVar) = prover.commit(A[idx], Scalar::random(&mut rng));
        //println!("curCom = {:?}", curCom);
        varArr.push(curVar.clone());
        comArr.push(curCom.clone());
    }

    
    // for idx in 0..A.len() {
    //     println!("{:}", idx);
    //     println!("comArr = {:?}", comArr[idx]);
    // }
 
    // Add 2-shuffle gadget constraints to the prover's constraint system
    
    variable_argument(&mut prover, &varArr, A.len(), circuitConfigArr)?;

    // Create a proof
    let proof = prover.prove(&bp_gens)?;

    Ok((proof, comArr))
}

pub fn verify(
    proof: R1CSProof,
    ComArr: &Vec<CompressedRistretto>,
    circuitConfigArr : &Vec<i32>,
) -> Result<(), R1CSError> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut verifier_transcript = Transcript::new(b"ShuffleTest");
    // Make a verifier instance
    let mut verifier = Verifier::new( &mut verifier_transcript);

    // Allocate high-level variables for A, B, C, D from commitments
    // let A_var = verifier.commit(A_com);
    // let B_var = verifier.commit(B_com);
    // let C_var = verifier.commit(C_com);
    // let D_var = verifier.commit(D_com);


    
    let mut varArr : Vec<Variable> = Vec::new();

    for idx in 0..ComArr.len() {
        //println!("idx = {:}", idx);
        let curVar = verifier.commit(ComArr[idx]);
        //println!("curCom = {:?}", curCom);
        varArr.push(curVar.clone());
    }

    // Add 2-shuffle gadget constraints to the verifier's constraint system
    variable_argument(&mut verifier, &varArr, ComArr.len(), circuitConfigArr)?;
    // Verify the proof
    Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_argument() -> Result<(),Box<dyn Error>>{
        let mut inputArr :  Vec<i32> = Vec::new();
        let file = File::open("/Users/lohitkrishnan/Documents/IBM/Blockchain/ZKP/bullet-proofs-repo/bulletproofs/file.txt")?;
        let mut lines = BufReader::new(file).lines();
        let len = lines.nth(1).expect("No line found at that position").unwrap();
        println!("{}", len); 
        println!("---><----");
    for line in lines {
        let l = line.unwrap();
        inputArr.push(l.parse::<i32>().unwrap());
        //println!("{}", l); 
    }
    for i  in inputArr.iter() {
        println!("{}", i);
    }
/*
    for line in BufReader::new(file).lines() {
        let l = line.unwrap();
        println!("{}", l); 
    }
    */
    println!("Printing Done!!");
        //assert!(variable_argument_helper(&vec![0; len.parse::<usize>().unwrap()], &inputArr).is_ok());
        //assert!(variable_argument_helper(&vec![1,2, 1, 4, 4], &inputArr).is_ok());
        assert!(variable_argument_helper(&vec![1,2, 1, 4, 4], &inputArr).is_ok());
        //assert!(variable_argument_helper(&vec![1,6, 6, 6, 6], &inputArr).is_ok());
        //assert!(variable_argument_helper(&vec![3, 3, 6, 3]).is_err());
        Ok(())
    }

    fn variable_argument_helper(varArr : &Vec<u32>, circuitConfigArr :  &Vec<i32>) -> Result<(), R1CSError> {
        let (proof, comVec) = prove(varArr, circuitConfigArr)?;
        //verify(proof, A_com, B_com, C_com, D_com)
        verify(proof, &comVec, circuitConfigArr)
    }
}