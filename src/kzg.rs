/// (K)ate (Z)averucha (G)oldberg Commitment Algorithm
///
/// (Be careful to pronounce Kate as Kahr-tey :]. https://www.cs.purdue.edu/homes/akate/howtopronounce.html)
use crate::poly::Polynomial;
use crate::srs::SRSParams;
use halo2::arithmetic::Field;
use halo2::halo2curves::bn256::{Fr, G1Affine, G2Affine};
use halo2::halo2curves::group::Curve;
use halo2::halo2curves::pairing::PairingCurveAffine;

pub struct Proof {
    pub(crate) polynomial_commitment: G1Affine,
    pub(crate) quotient_commitment: G1Affine,
    pub(crate) eval_of_challenge: Fr,
}

/// Proving
pub fn prove(polynomial: Polynomial, challenge: Fr, params: &SRSParams) -> Proof {
    let eval_of_challenge = polynomial.eval(&challenge);
    let mut numerator = polynomial.clone();
    numerator.coefficients[0] -= eval_of_challenge;
    let denominator = Polynomial::new(vec![challenge.neg(), Fr::ONE]);
    // Calculating Q(x) or aka quotient polynomial
    let quotient_polynomial = numerator / denominator;

    // [P(x)]_1 and [Q(x)]_1
    let polynomial_commitment = polynomial.commitment_g1(&params.g1);
    let quotient_commitment = quotient_polynomial.commitment_g1(&params.g1);

    Proof {
        polynomial_commitment,
        quotient_commitment,
        eval_of_challenge,
    }
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
    use halo2::{arithmetic::Field, halo2curves::bn256::Fr};
    use rand::thread_rng;

    #[test]
    fn test_kzg() {
        // Constructing Structured Reference String that is suitable to the given polynomial
        let k = 100;
        let params = trusted_setup_generator(k);
        // Polynomial created from the circuit constraints
        let circuit_size = 50;
        let polynomial = Polynomial::random(circuit_size);

        // Generating challange known by both prover and the verifier
        let rng = &mut thread_rng();
        let challenge = Fr::random(rng);

        let proof = prove(polynomial, challenge, &params);
        let res = verify(proof, challenge, &params);

        assert!(res);
    }
}