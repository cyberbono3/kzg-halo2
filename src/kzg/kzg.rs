/// (K)ate (Z)averucha (G)oldberg Commitment Algorithm
///
/// (Be careful to pronounce Kate as Kahr-tey :]. https://www.cs.purdue.edu/homes/akate/howtopronounce.html)
use crate::poly::Polynomial;
use crate::srs::SRSParams;
use halo2::arithmetic::Field;
use halo2::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2::halo2curves::group::Curve;
use halo2::halo2curves::pairing::PairingCurveAffine;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("empty coeffierror")]
    EmptyCoefficients(),
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub(crate) polynomial_commitment: G1Affine,
    pub(crate) quotient_commitment: G1Affine,
    pub(crate) eval_of_challenge: Fr,
}

/// Proving
pub fn prove(
    polynomial: Polynomial,
    challenge: Fr,
    params: &SRSParams,
) -> Result<Proof, ProofError> {
    let eval_of_challenge = polynomial.eval(&challenge);
    let mut numerator = polynomial.clone();
    let coeffs = numerator.coefficients_mut();
    if coeffs.is_empty() {
        return Err(ProofError::EmptyCoefficients());
    }
    coeffs[0] -= eval_of_challenge;
    let denominator = Polynomial::new(vec![challenge.neg(), Fr::ONE]);
    let quotient_polynomial = numerator / denominator;

    // [P(x)]_1 and [Q(x)]_1
    let polynomial_commitment = polynomial.commitment_g1(&params.g1);
    let quotient_commitment = quotient_polynomial.commitment_g1(&params.g1);

    Ok(Proof {
        polynomial_commitment,
        quotient_commitment,
        eval_of_challenge,
    })
}

/// Verification algorithm
pub fn verify(proof: Proof, challenge: Fr, params: &SRSParams) -> bool {
    // s is the secret that we don't know. Also, as known as toxic waste.
    let generator_g2 = G2Affine::generator();
    let challenge_g2 = generator_g2 * challenge;
    let s_sub_challenge = params.g2[1] - challenge_g2;

    let pair_1 = proof
        .quotient_commitment
        .pairing_with(&s_sub_challenge.to_affine());

    // [eval_of_challenge]1
    let generator_g1 = G1Affine::generator();
    let eval_of_challenge_g1 = generator_g1 * proof.eval_of_challenge;
    let polynomial_commitment_sub_y = proof.polynomial_commitment - eval_of_challenge_g1;

    // Right pair (Pair two)
    // e([P(x)]_1 - [eval_of_challenge]_1, G2)
    let pair_2 = polynomial_commitment_sub_y
        .to_affine()
        .pairing_with(&generator_g2);

    pair_1 == pair_2
}

#[cfg(test)]
mod tests {
    use super::{prove, verify};
    use crate::poly::Polynomial;
    use crate::srs::trusted_setup_generator;
    use crate::{fr_vec, poly_vec};
    use halo2::{arithmetic::Field, halo2curves::bn256::Fr};
    use rand::thread_rng;

    #[test]
    fn test_random_polynomial_kzg() {
        // Constructing Structured Reference String that is suitable to the given polynomial
        let k = 100;
        let params = trusted_setup_generator(k);
        // Polynomial created from the circuit constraints
        let circuit_size = 50;
        let polynomial = Polynomial::random(circuit_size);

        // Generating challange known by both prover and the verifier
        let rng = &mut thread_rng();
        let challenge = Fr::random(rng);

        let proof = prove(polynomial, challenge, &params).unwrap();
        let res = verify(proof, challenge, &params);

        assert!(res);
    }

    #[test]
    fn test_zero_polynomial_kzg() {
        let k = 10; // The size of the SRS (large enough for your polynomial)
        let params = trusted_setup_generator(k);

        // P(x) = 0  (all coefficients are zero)
        let degree = 5;
        let polynomial = Polynomial::new(fr_vec!(0; degree + 1));

        // Random challenge
        let mut rng = thread_rng();
        let challenge = Fr::random(&mut rng);

        let proof = prove(polynomial, challenge, &params).unwrap();
        let verified = verify(proof, challenge, &params);

        assert!(
            verified,
            "Zero polynomial proof verification failed but should succeed"
        );
    }

    #[test]
    fn test_linear_polynomial_kzg() {
        let k = 10;
        let params = trusted_setup_generator(k);

        // P(x) = a*x + b
        let polynomial = poly_vec!(7, 5);

        // Random challenge
        let mut rng = thread_rng();
        let challenge = Fr::random(&mut rng);

        // Expected evaluation
        let expected_eval = polynomial.eval(&challenge);

        let proof = prove(polynomial, challenge, &params).unwrap();
        let verified = verify(proof.clone(), challenge, &params);

        assert!(verified, "Linear polynomial proof verification failed");

        // Confirm the in-proof evaluation matches the direct computation
        assert_eq!(
            proof.eval_of_challenge, expected_eval,
            "Linear polynomial: evaluation mismatch"
        );
    }

    // 3. Known polynomial with a known challenge (explicit evaluation check)
    #[test]
    fn test_known_polynomial_eval() {
        let k = 10;
        let params = trusted_setup_generator(k);

        // P(x) = 3*x^2 + 5*x + 7
        let polynomial = poly_vec!(7, 5, 3);

        // Let's pick challenge = 2
        let challenge = Fr::from(2u64);

        // Expected: P(2) = 3*2^2 + 5*2 + 7 = 3*4 + 10 + 7 = 12 + 10 + 7 = 29
        let expected_eval = Fr::from(29u64);

        let proof = prove(polynomial, challenge, &params).unwrap();
        let verified = verify(proof.clone(), challenge, &params);

        assert!(verified, "Known polynomial proof verification failed");
        assert_eq!(
            proof.eval_of_challenge, expected_eval,
            "Known polynomial: evaluation mismatch"
        );
    }
}
