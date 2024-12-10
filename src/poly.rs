use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine, G1, G2},
        ff::PrimeField,
        group::Curve,
    },
};

use std::ops::{Add, AddAssign, Sub, Mul, Div};
use rand::thread_rng;

/// Polynomial Structure
#[derive(Clone, Debug)]
pub struct Polynomial {
    // Coefficients of the polynomial
    pub(crate) coefficients: Vec<Fr>,
}

// f(x)  =  2 * x^0 + 5 * x^1 + 6 * x^2
// coeff = [2, 5, 6]
// p(1)  =  2 * 1   + 5 * 1   + 6 * 1
impl Polynomial {
    /// Creates a new polynomial from given vector
    pub fn new(coefficients: Vec<Fr>) -> Self {
        Self { coefficients }
    }

    /// Creates a new random polynomial with given length
    pub fn random(length: usize) -> Self {
        let rng = &mut thread_rng();
        let coefficients: Vec<Fr> = (0..length)
        .map(|_| Fr::random(rng.clone()))
        .collect();
        Self {
            coefficients
        }
    }

    /// Evaluates polynomial on the given value
    pub fn eval(&self, x: &Fr) -> Fr {
        self.coefficients
        .iter()
        .fold((Fr::ZERO, Fr::ONE),  |(eval, point), coeff| {
             (eval + coeff * point, point * x)
        }).0
    }

    
    /// This function will build a polynomial from values and given domain.
    /// Will use lagrange interpolation.
    pub fn lagrange(values: Vec<Fr>, domain: Vec<Fr>) -> Self {
        let mut lagrange_polynomial = Polynomial::new(vec![Fr::ZERO]);
        for i in 0..values.len() {
            let mut mul_numerator = Polynomial::new(vec![Fr::ONE]);
            let mut mul_denominator = Fr::ONE;

            for j in 0..values.len() {
                if i == j {
                    continue;
                }
                let numerator =
                    Polynomial::new(vec![Fr::from_u128(j.try_into().unwrap()).neg(), Fr::ONE]);
                let denominator = domain[i] - domain[j];
                mul_numerator = mul_numerator * numerator.clone();
                mul_denominator *= denominator;
            }

            let numerator =
                mul_numerator * Polynomial::new(vec![mul_denominator
                    .invert()
                    .unwrap()]);

            let res = Polynomial::new(
                numerator
                    .coefficients
                    .iter()
                    .map(|x| x * values[i])
                    .collect(),
            );

            lagrange_polynomial += res;
        }
        lagrange_polynomial
    }


    /// Makes the commitment for the given polynomial and SRS
    pub fn commitment_g1(&self, srs_1: &[G1Affine]) -> G1Affine {
        self.coefficients
        .iter()
        .zip(srs_1.iter())
        .fold(G1::default(), 
            |acc, (coeff, srs) |  
                acc + srs * coeff).to_affine()
    }

    /// Makes the commitment for the given polynomial and SRS
    pub fn commitment_g2(&self, srs_2: &[G2Affine]) -> G2Affine {
        self.coefficients
        .iter()
        .zip(srs_2.iter())
        .fold(G2::default(), 
            |acc, (coeff, srs) |  
                acc + srs * coeff).to_affine()
    }
}

impl Add for Polynomial {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut big = self.coefficients.clone().max(rhs.coefficients.clone());
        let small = self.coefficients.clone().min(rhs.coefficients.clone());
        for i in 0..small.len() {
            big[i] += small[i];
        }
        Polynomial::new(big)
    }
}

impl AddAssign for Polynomial {
    fn add_assign(&mut self, rhs: Self) {
        let max_len = self.coefficients.len().max(rhs.coefficients.len());
        
        // Ensure self.coefficients has the correct size
        if self.coefficients.len() < max_len {
            self.coefficients.resize(max_len, Fr::zero());
        }
        
        for i in 0..rhs.coefficients.len() {
            self.coefficients[i] += rhs.coefficients[i];
        }
    }
}

impl Sub for Polynomial {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let mut big = self.coefficients.clone().max(rhs.coefficients.clone());
        let small = self.coefficients.clone().min(rhs.coefficients.clone());
        for i in 0..small.len() {
            big[i] -= small[i];
        }
        Polynomial::new(big)
    }
}

impl Mul for Polynomial {
    type Output = Self;
    fn mul(self, rhs: Self ) -> Self {
        let mut result = vec![Fr::zero(); self.coefficients.len() + rhs.coefficients.len() - 1];
        for i in 0..self.coefficients.len() {
            for j in 0..rhs.coefficients.len() {
                result[i + j] += self.coefficients[i] * rhs.coefficients[j];
            }
        }
        Polynomial::new(result)
    }
}


// f(x) = (x - 2)(x - 3) = roots are 2, 3
// f(a) = 0, a = root of p
// f(x) = 1*x^2 + 2*x^1 + 1*x^0
// z = 5
// f(z) = 1*25 + 2*5 + 1 = 36 = y
// q(x) = (f(x) - y) / (x - z)
//      = (1*x^2 + 2*x^1 + 1 - 36) / (x - 5)
//      = (1*x^2 + 2*x^1 - 35) / (x - 5)
//      = (x + 7)(x - 5) / (x - 5)
//      = (x + 7)
/// Calculates quotient using long division algorithm
impl Div for Polynomial {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        // Here assigning it in reverse order and at the end of the function it will be reverted.
        let coefficients: Vec<Fr> = self.coefficients.iter().cloned().rev().collect();

        let mut quotient = (0..coefficients.len() - 2)
        .fold(vec![coefficients[0]], |mut acc, i | {
             let last = acc.last().unwrap() ;
             let next = coefficients[i+1] - (last * rhs.coefficients[0]);
             acc.push(next);
             acc
        });

        // Revert quotient to correct positioning for the whole algorithm
        quotient.reverse();

        Polynomial::new(quotient)

    }
}
