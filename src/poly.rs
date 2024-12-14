use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine, G1, G2},
        ff::PrimeField,
        group::Curve,
    },
};

use rand::thread_rng;
use std::borrow::Cow;
use std::ops::{Add, AddAssign, Div, Mul, Sub};

/// Macro to create a `Vec<Fr>` using integers.
///
/// # Example
/// ```
/// # use halo2::halo2curves::bn256::Fr;
/// # use halo2_project::fr_vec;
/// let vector = fr_vec![0, 1, 2, 3];
/// assert_eq!(vector,vec![Fr::from(0),Fr::from(1),Fr::from(2),Fr::from(3)]);
/// ```
#[macro_export]
macro_rules! fr_vec {
    ($($x:expr),+ $(,)?) => {
        vec![$(Fr::from($x)),+]
    };
}

/// Macro to create a `Polynomial` directly from integers.
///
/// # Example
/// ```
/// # use halo2::halo2curves::bn256::Fr;
/// # use halo2_project::poly::Polynomial;
/// # use halo2_project::poly_vec;
/// # use halo2_project::fr_vec;
///
/// let poly: Polynomial = poly_vec![1, 2, 3];
/// assert_eq!(
///     poly.coefficients(),
///     vec![
///         Fr::from(1),
///         Fr::from(2),
///         Fr::from(3),
///     ]
/// );
/// ```
#[macro_export]
macro_rules! poly_vec {
    ($($x:expr),+ $(,)?) => {
        Polynomial::from(fr_vec![$($x),+])
    };
}

/// Polynomial Structure
#[derive(Clone, Debug)]
pub struct Polynomial<'coeffs> {
    // Coefficients of the polynomial
    coefficients: Cow<'coeffs, [Fr]>,
}

// f(x)  =  2 * x^0 + 5 * x^1 + 6 * x^2
// coeff = [2, 5, 6]
// f(1)  =  2 * 1   + 5 * 1   + 6 * 1
impl<'coeffs> Polynomial<'coeffs> {
    /// Creates a new polynomial from given vector
    pub fn new(coefficients: Vec<Fr>) -> Self {
        let coefficients = Cow::Owned(coefficients);
        Self { coefficients }
    }

    /// Like [`Self::new`], but without owning the coefficients.
    pub fn new_borrowed(coefficients: &'coeffs [Fr]) -> Self {
        let coefficients = Cow::Borrowed(coefficients);
        Self { coefficients }
    }

    /// Creates a mutable reference to Polynomial coefficients to mutate them inplace
    pub fn coefficients_mut(&mut self) -> &mut Vec<Fr> {
        self.coefficients.to_mut()
    }

    pub fn coefficients(&self) -> Vec<Fr> {
        self.coefficients.to_vec()
    }

    /// Creates a new random polynomial with given length
    pub fn random(length: usize) -> Self {
        let rng = &mut thread_rng();
        let coefficients: Vec<Fr> = (0..length).map(|_| Fr::random(rng.clone())).collect();
        coefficients.into()
    }

    /// Evaluates polynomial on the given value
    pub fn eval(&self, x: &Fr) -> Fr {
        self.coefficients
            .iter()
            .fold((Fr::ZERO, Fr::ONE), |(eval, point), coeff| {
                (eval + coeff * point, point * x)
            })
            .0
    }

    /// This function will build a polynomial from values and given domain.
    /// Will use lagrange interpolation.
    pub fn lagrange(values: &[Fr], domain: &[Fr]) -> Self {
        let mut lagrange_polynomial = vec![Fr::ZERO].into();
        for i in 0..values.len() {
            let mut mul_numerator: Polynomial = vec![Fr::ONE].into();
            let mut mul_denominator = Fr::ONE;

            for j in 0..values.len() {
                if i == j {
                    continue;
                }
                let numerator: Polynomial =
                    vec![Fr::from_u128(j.try_into().unwrap()).neg(), Fr::ONE].into();
                let denominator = domain[i] - domain[j];
                mul_numerator = mul_numerator * numerator.clone();
                mul_denominator *= denominator;
            }

            let numerator =
                mul_numerator * Polynomial::new(vec![mul_denominator.invert().unwrap()]);

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
            .fold(G1::default(), |acc, (coeff, srs)| acc + srs * coeff)
            .to_affine()
    }

    /// Makes the commitment for the given polynomial and SRS
    pub fn commitment_g2(&self, srs_2: &[G2Affine]) -> G2Affine {
        self.coefficients
            .iter()
            .zip(srs_2.iter())
            .fold(G2::default(), |acc, (coeff, srs)| acc + srs * coeff)
            .to_affine()
    }
}

impl<'coeffs> PartialEq for Polynomial<'coeffs> {
    fn eq(&self, other: &Polynomial<'coeffs>) -> bool {
        self.coefficients
            .iter()
            .zip(other.coefficients.iter())
            .all(|(x, y)| x == y)
    }
}

impl<'coeffs> Add for Polynomial<'coeffs> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let mut big = self.coefficients.to_vec().max(rhs.coefficients.to_vec());
        let small = self.coefficients.to_vec().min(rhs.coefficients.to_vec());
        for i in 0..small.len() {
            big[i] += small[i];
        }
        Self::new(big)
    }
}

impl<'coeffs> AddAssign for Polynomial<'coeffs> {
    fn add_assign(&mut self, rhs: Self) {
        let coeffs = self.coefficients.to_mut();
        let coeffs_len = coeffs.len();
        let max_len = coeffs_len.max(rhs.coefficients.len());

        // Ensure self.coefficients has the correct size
        if coeffs_len < max_len {
            coeffs.resize(max_len, Fr::zero());
        }

        // Add corresponding coefficients
        for (a, b) in coeffs.iter_mut().zip(rhs.coefficients.iter()) {
            *a += *b;
        }
    }
}

impl<'coeffs> Sub for Polynomial<'coeffs> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let mut big = self.coefficients.to_vec().max(rhs.coefficients.to_vec());
        let small = self.coefficients.clone().min(rhs.coefficients.clone());
        for i in 0..small.len() {
            big[i] -= small[i];
        }
        Self::new(big)
    }
}

impl<'coeffs> Mul for Polynomial<'coeffs> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let mut result = vec![Fr::zero(); self.coefficients.len() + rhs.coefficients.len() - 1];
        for i in 0..self.coefficients.len() {
            for j in 0..rhs.coefficients.len() {
                result[i + j] += self.coefficients[i] * rhs.coefficients[j];
            }
        }
        Polynomial::new(result)
    }
}

impl<'coeffs> Div for Polynomial<'coeffs> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        // Here assigning it in reverse order and at the end of the function it will be reverted.
        let mut coefficients = self.coefficients.to_vec();
        coefficients.reverse();

        // Biggest degree of the quotient will always be the biggest degree's coefficient from
        // the numerator polynomial. That is why it is assigned here
        let mut quotient: Vec<Fr> = vec![coefficients[0]];

        // Long division algorithm
        for i in 0..coefficients.len() - 2 {
            quotient.push(coefficients[i + 1] - quotient[i] * rhs.coefficients[0]);
        }

        // Revert quotient to correct positioning for the whole algorithm
        quotient.reverse();

        Self::new(quotient)
    }
}

impl From<Vec<Fr>> for Polynomial<'static> {
    fn from(vec: Vec<Fr>) -> Self {
        Self::new(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_new() {
        let coeffs = fr_vec![1, 2, 3];
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
        let poly: Polynomial = fr_vec![2, 5, 6].into(); // 2 + 5x + 6x^2
        let x = Fr::from(1); // Test at x = 1
        let result = poly.eval(&x);
        let expected = Fr::from(13); // 2 + 5*1 + 6*1^2
        assert_eq!(result, expected);
    }

    #[test]
    fn test_polynomial_addition() {
        let poly1: Polynomial = fr_vec![1, 2].into(); // 1 + 2x
        let poly2 = fr_vec![3, 4].into(); // 3 + 4x
        let result = poly1 + poly2;
        assert_eq!(result.coefficients, fr_vec![4, 6]); // 4 + 6x
    }

    #[test]
    fn test_polynomial_subtraction() {
        let poly1: Polynomial = fr_vec![5, 7].into(); // 5 + 7x
        let poly2 = fr_vec![3, 4].into(); // 3 + 4x
        let result = poly1 - poly2;
        assert_eq!(result.coefficients, fr_vec![2, 3]); // 2 + 3x
    }

    #[test]
    fn test_polynomial_multiplication() {
        let poly1 = Polynomial::new(fr_vec![1, 1]); // 1 + x
        let poly2 = Polynomial::new(fr_vec![1, 1]); // 1 + x
        let result = poly1 * poly2;
        assert_eq!(result.coefficients, fr_vec![1, 2, 1]); // 1 + 2x + x^2
    }

    #[test]
    fn test_polynomial_division() {
        // Dividend: x^2 + 3x + 2
        let poly1: Polynomial = fr_vec![2, 3, 1].into();

        // Divisor: x + 1
        let poly2 = fr_vec![1, 1].into();

        // Expected Quotient: x + 2
        let expected_quotient: Polynomial = fr_vec![2, 1].into();

        // Perform long division
        let result = poly1 / poly2;

        // Check if the result matches the expected quotient
        assert_eq!(result, expected_quotient);
    }

    #[test]
    fn test_polynomial_lagrange() {
        let domain = fr_vec![0, 1, 2];
        let values = fr_vec![2, 5, 10];
        let poly = Polynomial::lagrange(&values, &domain);

        for (i, x) in domain.iter().enumerate() {
            assert_eq!(poly.eval(x), values[i]);
        }
    }

    #[test]
    fn test_add_assign_same_length() {
        let mut poly1 = poly_vec![1, 2, 3];

        let poly2 = poly_vec![4, 5, 6];

        poly1 += poly2;

        assert_eq!(poly1, poly_vec![5, 7, 9]);
    }

    #[test]
    fn test_add_assign_different_length_rhs_longer() {
        let mut poly1 = poly_vec![1, 2];

        let poly2 = poly_vec![3, 4, 5];

        poly1 += poly2;

        assert_eq!(poly1, poly_vec![4, 6, 5]);
    }

    #[test]
    fn test_add_assign_different_length_lhs_longer() {
        let mut poly1 = poly_vec![2, 3, 4];

        let poly2 = poly_vec![1, 1];
        poly1 += poly2;

        assert_eq!(poly1, poly_vec![3, 4, 4]);
    }

    // TODO tesst commitments
}
