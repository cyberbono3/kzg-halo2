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
// f(1)  =  2 * 1   + 5 * 1   + 6 * 1
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
        coefficients.into()
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
        let mut lagrange_polynomial = vec![Fr::ZERO].into();
        for i in 0..values.len() {
            let mut mul_numerator : Polynomial = vec![Fr::ONE].into();
            let mut mul_denominator = Fr::ONE;

            for j in 0..values.len() {
                if i == j {
                    continue;
                }
                let numerator: Polynomial = vec![Fr::from_u128(j.try_into().unwrap()).neg(), Fr::ONE].into();
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
                acc + srs * coeff)
        .to_affine()
    }

    /// Makes the commitment for the given polynomial and SRS
    pub fn commitment_g2(&self, srs_2: &[G2Affine]) -> G2Affine {
        self.coefficients
        .iter()
        .zip(srs_2.iter())
        .fold(G2::default(), 
            |acc, (coeff, srs) |  
                acc + srs * coeff)
        .to_affine()
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


impl Div for Polynomial {
    type Output = Self;


    // test passes 
    fn div(self, rhs: Self) -> Self {
        let mut dividend = self.coefficients.clone();
        let divisor = rhs.coefficients.clone();

        let mut quotient = vec![Fr::ZERO; dividend.len() - divisor.len() + 1];

        // Perform polynomial division
        for i in (0..=dividend.len() - divisor.len()).rev() {
            let coeff = dividend[i + divisor.len() - 1] * divisor.last().unwrap().invert().unwrap();
            quotient[i] = coeff;

            for j in 0..divisor.len() {
                dividend[i + j] -= coeff * divisor[j];
            }
        }

        // Remove trailing zeros from quotient
         while let Some(c) = quotient.last() {
            if c.is_zero_vartime() {
                quotient.pop();
            } else {
                break;
            }
        }

        Polynomial::new(quotient)
    }
}

impl From<Vec<Fr>> for Polynomial {
    fn from(vec: Vec<Fr>) -> Self {
        Self::new(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_new() {
        let coeffs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let poly: Polynomial = coeffs.clone().into();
        assert_eq!(poly.coefficients, coeffs);
    }

    #[test]
    fn test_polynomial_random() {
        let poly = Polynomial::random(3);
        assert_eq!(poly.coefficients.len(), 3);
    }

    #[test]
    fn test_polynomial_eval() {
        let poly: Polynomial = vec![Fr::from(2), Fr::from(5), Fr::from(6)].into(); // 2 + 5x + 6x^2
        let x = Fr::from(1); // Test at x = 1
        let result = poly.eval(&x);
        let expected = Fr::from(13); // 2 + 5*1 + 6*1^2
        assert_eq!(result, expected);
    }

    #[test]
    fn test_polynomial_addition() {
        let poly1: Polynomial = vec![Fr::from(1), Fr::from(2)].into(); // 1 + 2x
        let poly2 = vec![Fr::from(3), Fr::from(4)].into(); // 3 + 4x
        let result = poly1 + poly2;
        assert_eq!(result.coefficients, vec![Fr::from(4), Fr::from(6)]); // 4 + 6x
    }

    #[test]
    fn test_polynomial_subtraction() {
        let poly1: Polynomial = vec![Fr::from(5), Fr::from(7)].into(); // 5 + 7x
        let poly2 = vec![Fr::from(3), Fr::from(4)].into(); // 3 + 4x
        let result = poly1 - poly2;
        assert_eq!(result.coefficients, vec![Fr::from(2), Fr::from(3)]); // 2 + 3x
    }

    #[test]
    fn test_polynomial_multiplication() {
        let poly1 = Polynomial::new(vec![Fr::from(1), Fr::from(1)]); // 1 + x
        let poly2 = Polynomial::new(vec![Fr::from(1), Fr::from(1)]); // 1 + x
        let result = poly1 * poly2;
        assert_eq!(result.coefficients, vec![Fr::from(1), Fr::from(2), Fr::from(1)]); // 1 + 2x + x^2
    }

    #[test]
    fn test_polynomial_division1() {
        let poly1 = Polynomial::new(vec![Fr::from(1), Fr::from(0), Fr::from(1).neg()]); // x^2 + (field order - 1)
        let poly2 = Polynomial::new(vec![Fr::from(1), Fr::from(1).neg()]); // x + (field order - 1)

        let result = poly1 / poly2;

        assert_eq!(result.coefficients, vec![Fr::from(1), Fr::from(1)]); // x + 1
    }

    #[test]
    fn test_polynomial_division2() {
        // Dividend: x^2 + 3x + 2
        let poly1: Polynomial = vec![Fr::from(2), Fr::from(3), Fr::from(1)].into();

        // Divisor: x + 1
        let poly2 = vec![Fr::from(1), Fr::from(1)].into();

        // Expected Quotient: x + 2
        let expected_quotient: Polynomial = vec![Fr::from(2), Fr::from(1)].into();

        // Perform long division
        let result = poly1 / poly2;

        // Check if the result matches the expected quotient
        assert_eq!(result.coefficients, expected_quotient.coefficients);
    }

    #[test]
    fn test_polynomial_lagrange() {
        let domain = vec![Fr::from(0), Fr::from(1), Fr::from(2)];
        let values = vec![Fr::from(2), Fr::from(5), Fr::from(10)];
        let poly = Polynomial::lagrange(values.clone(), domain.clone());

        for (i, x) in domain.iter().enumerate() {
            assert_eq!(poly.eval(x), values[i]);
        }
    }

    // TODO tesst commitments
}
