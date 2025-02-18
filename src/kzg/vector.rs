use std::ops::Sub;

use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G2Affine},
        group::Curve,
        pairing::PairingCurveAffine,
    },
};

use crate::fr_vec;
use crate::kzg::kzg::Proof;
use crate::{poly::Polynomial, srs::SRSParams};

pub fn prove(vector: &[Fr], challenge: &[Fr], params: &SRSParams) -> Proof {
    // Constructing vector polynomial with lagrange interpolation
    let polynomial = Polynomial::lagrange(vector, &fr_vec![0, 1, 2, 3]);

    let numerator = polynomial.clone() - Polynomial::lagrange(vector, challenge);

    // Constructing zero polynomial Z(x)
    let zero_polynomial = challenge
        .iter()
        .fold(Polynomial::new(fr_vec!(1)), |acc, &item| {
            acc * Polynomial::new(vec![-item, Fr::ONE])
        });
    let denominator = zero_polynomial;
    // Calculating Q(x) or aka quotient polynomial
    let quotient_polynomial = numerator / denominator;

    // [P(x)]_1 and [Q(x)]_1
    let polynomial_commitment = polynomial.commitment_g1(&params.g1);
    let quotient_commitment = quotient_polynomial.commitment_g1(&params.g1);

    let eval_of_challenge = Fr::ZERO;
    Proof {
        polynomial_commitment,
        quotient_commitment,
        eval_of_challenge,
    }
}

/// Verification algorithm
pub fn verify(proof: Proof, vector: &[Fr], challenge: &[Fr], params: &SRSParams) -> bool {
    let generator_g2 = G2Affine::generator();

    // Constructing challenge polynomial I(x)
    let challenge_polynomial = Polynomial::lagrange(vector, challenge);
    let challenge_polynomial_commitment = challenge_polynomial.commitment_g1(&params.g1);

    // Constructing zero polynomial Z(x)
    let mut zero_polynomial = Polynomial::new(vec![Fr::ONE]);
    for items in challenge.iter() {
        zero_polynomial *= vec![-items, Fr::ONE].into();
    }
    let zero_polynomial_commitment = zero_polynomial.commitment_g2(&params.g2);

    // Left pair (Pair one)
    // e([Q(x)]_1, Z(x)_2)
    let pair_1 = proof
        .quotient_commitment
        .pairing_with(&zero_polynomial_commitment);

    // P(x)_1 - I(x)_1
    let polynomial_commitment_sub_challenge_commitment = proof
        .polynomial_commitment
        .sub(challenge_polynomial_commitment);

    // Right pair (Pair two)
    // e([P(x)]_1 - I(x)_1, G2)
    let pair_2 = polynomial_commitment_sub_challenge_commitment
        .to_affine()
        .pairing_with(&generator_g2);

    // We calculated Q(x) as (P(x) - I(x)) / Z(x)
    // This assertion checks if:
    // [Q(s)]_1 * Z(s)_2 == [P(s) - I(s)]_1
    // Thanks to pairing we can use s without knowing it.
    // That means prover has the vector and that index returns the value from the vector.
    pair_1 == pair_2
}

//#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::srs::trusted_setup_generator;

    use halo2::{
        arithmetic::Field,
        halo2curves::{bn256::Fr, ff::PrimeField},
    };

    pub fn generate_test_data() -> (Vec<Fr>, Vec<Fr>, SRSParams) {
        // Constructing Structured Reference String that is suitable to the given polynomial
        let k = 123;
        let params = trusted_setup_generator(k);
        // Vector that is known to prover and verifier
        let vector = vec![
            Fr::ONE,
            Fr::ONE + Fr::ONE + Fr::ONE + Fr::ONE + Fr::ONE,
            Fr::ONE + Fr::ONE,
            Fr::ONE + Fr::ONE + Fr::ONE,
        ];

        // Creating vector indexes as challanges known by both prover and the verifier
        let challenge = fr_vec![0, 1, 2, 3];

        (vector, challenge, params)
    }

    #[test]
    fn kzg_vector_test() {
        let (vector, challenge, params) = generate_test_data();

        let proof = prove(&vector, &challenge, &params);
        let res = verify(proof, &vector, &challenge, &params);

        assert!(res);
    }
}
