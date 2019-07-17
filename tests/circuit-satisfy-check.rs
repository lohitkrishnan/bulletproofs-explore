#![allow(non_snake_case)]

extern crate num_bigint;
extern crate bigint;
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bigint::uint::U256;
use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use num_bigint::{BigInt, Sign};

pub fn getEquation(
    //cs: &mut <Type as bulletproofs::r1cs::RandomizableConstraintSystem>::RandomizedCS,
    varArr: &Vec<u128>,
    circuitConfigArr: &Vec<String>,
    mut i: usize,
) -> BigInt {
    //let mut a: LinearCombination = LinearCombination::default();
    let mut a : BigInt = BigInt::new(Sign::Plus, vec![0]);
    //return a;

    
    //let mut a : BigInt = BigInt::new(sign: Sign, digits: Vec<u32>)
    //let mut n_terms = circuitConfigArr[i];
    let mut n_terms = circuitConfigArr[i].parse::<i32>().unwrap();;
    i = i + 1;
    let mut term_cnt = 0;
    while term_cnt < n_terms {
        //i = i + 2;
        let mut varNum = circuitConfigArr[i].parse::<i32>().unwrap();
        let mut coeff = circuitConfigArr[i + 1].clone();
        let mut isNeg = false;
        if (circuitConfigArr[i + 1].starts_with('-')) {
            coeff = coeff[1..].to_string();

            isNeg = true;
        }

        let mut coeff_bits = [0u8; 32];
        bigint::uint::U256::from_dec_str(&coeff)
            .unwrap()
            .to_little_endian(&mut coeff_bits);
        //bigint::uint::U256::from_dec_str(&coeff).unwrap().to_little_endian(&mut coeff_bits);
        let mut coeff_scalar = Scalar::from_bits(coeff_bits);
        let mut coeff_bigint = BigInt::from_bytes_le(Sign::Plus, &coeff_bits);

        if isNeg {
            //coeff = coeff * -1;
            //a  =  a - Scalar::from(coeff as u32)*varArr[varNum as usize];
            a = a - coeff_bigint * varArr[varNum as usize];
        } else {
            //a  =  a + Scalar::from(coeff as u32)*varArr[varNum as usize];
            a = a + coeff_bigint * varArr[varNum as usize];
        }

        i = i + 2;
        term_cnt = term_cnt + 1;
    }
    return a;
    
}

pub fn check_circuit_satisfy(
    rawVar: &[u128],
    circuitConfigArr: &Vec<String>,
) -> usize {
    let A: Vec<u128> = rawVar.iter().map(|&x| x.into()).collect();
     let mut i: usize = 0;
     let mut start : usize = 0;

    while i < circuitConfigArr.len() {
        //println!("before a - {}",i);
        start = i;
        let mut a = getEquation(&A, circuitConfigArr, i);
        //println!("before a - {}",i);
        circuitConfigArr[i].parse::<i32>().unwrap();

        //i = i + (circuitConfigArr[i] as usize)*2  + 1;
        i = i + circuitConfigArr[i].parse::<usize>().unwrap() * 2 + 1;
        //println!("after a - {}",i);
        let mut b = getEquation(&A, circuitConfigArr, i);
        //println!("after a - {}",i);
        //i = i + (circuitConfigArr[i] as usize)*2  + 1;
        i = i + circuitConfigArr[i].parse::<usize>().unwrap() * 2 + 1;
        //println!("after b - {}",i);
        let mut c = getEquation(&A, circuitConfigArr, i);
        //println!("after b - {}",i);
        //i = i + (circuitConfigArr[i] as usize)*2  + 1;
        i = i + circuitConfigArr[i].parse::<usize>().unwrap() * 2 + 1;
        //println!("after c - {}",i);

        
        let mut ab : BigInt = a*b;
        println!("ab = {:}", ab);
        println!("c = {:}",c);
        println!("start = {:}",start);
        if(ab != c) {
            return start+2;
        }
    }
    return i;
}


pub fn check_satisfiability(
    rawVar: &[u128],
    circuitConfigArr: &Vec<String>,
) ->  usize {
    return check_circuit_satisfy(&rawVar, circuitConfigArr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn circuit_satisfy_check() -> Result<(), Box<dyn Error>> {
        let filename = "/Users/lohitkrishnan/Documents/IBM/Blockchain/ZKP/bullet-proofs-repo/bulletproofs/hash_const_r1cs_constraints_converted.txt";
        //let filename = "/Users/lohitkrishnan/Documents/IBM/Blockchain/ZKP/bullet-proofs-repo/bulletproofs/file.txt";
        //let filename = "/Users/lohitkrishnan/Documents/IBM/Blockchain/ZKP/bullet-proofs-repo/bulletproofs/circuit-ex2.txt";

        let mut inputArr1: Vec<String> = Vec::new();
        let file = File::open(filename)?;
        let mut lines = BufReader::new(file).lines();
        let len = lines
            .nth(0)
            .expect("No line found at that position")
            .unwrap();
        for line in lines {
            let l = line.unwrap();
            //inputArr.push(l.parse::<i32>().unwrap());
            inputArr1.push(l.parse::<String>().unwrap());
            //println!("{}", l);
        }
        println!("string Array is -------");
        // for i  in inputArr1.iter() {
        //     println!("{}", i);
        // }
        //-----
        let witnessFileName = "/Users/lohitkrishnan/Documents/IBM/Blockchain/ZKP/bullet-proofs-repo/bulletproofs/hash_const_r1cs_witness_converted.txt";
        //let witnessFileName = "/Users/lohitkrishnan/Documents/IBM/Blockchain/ZKP/bullet-proofs-repo/bulletproofs/sample-witness-input.txt";
        //let witnessFileName = "/Users/lohitkrishnan/Documents/IBM/Blockchain/ZKP/bullet-proofs-repo/bulletproofs/wit-ex2.txt";
        let mut witnessInput: Vec<u128> = Vec::new();
        witnessInput.push(0u128);
        let file = File::open(witnessFileName)?;
        let mut lines = BufReader::new(file).lines();

        for line in lines {
            let l = line.unwrap();
            witnessInput.push(l.parse::<u128>().unwrap());
        }
        println!("Witness Vector Size = {}", witnessInput.len());

        
        //assert!(circuit_satisfy_check_helper(&vec![0; len.parse::<usize>().unwrap()], &inputArr).is_ok());
        //assert!(circuit_satisfy_check_helper(&vec![1,2, 1, 4, 4], &inputArr1).is_ok());
        //assert!(circuit_satisfy_check_helper(&vec![0,2, 1, 4, 4], &inputArr1).is_ok());
        assert!(circuit_satisfy_check_helper(&witnessInput, &inputArr1).is_ok());
        //println!("{:?}", circuit_satisfy_check_helper(&witnessInput, &inputArr1).err());
        //assert!(circuit_satisfy_check_helper(&vec![1,1, 1, 2, 4], &inputArr1).is_ok());
        //assert!(circuit_satisfy_check_helper(&vec![3, 3, 6, 3]).is_err());
        Ok(())
    }

    fn circuit_satisfy_check_helper(
        varArr: &Vec<u128>,
        circuitConfigArr: &Vec<String>,
    ) -> Result<(), R1CSError> {
        let mut total_proving = Duration::new(0, 0);
        let start = Instant::now();
    
        let idx = check_satisfiability(varArr, circuitConfigArr);
        println!("Final idx = {:}", idx);

        total_proving += start.elapsed();
        println!("Total proving time  {:?} seconds", total_proving);
        Ok(())
       
    }
}
