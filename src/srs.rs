use halo2::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine},
        group::Curve,
    },
};
use rand::thread_rng;

// SRSParams are used in trusted_setup
pub struct SRSParams {
    pub g1: Vec<G1Affine>,
    pub g2: Vec<G2Affine>,
}

/// Builds SRS for the algorithm.
pub fn trusted_setup_generator(length: usize) -> SRSParams {
    let generator_g1 = G1Affine::generator();
    let generator_g2 = G2Affine::generator();
    let rng = &mut thread_rng();
    // This toxic waste is the value that we create SRS by using it.
    // In real life implementations, programmers uses a SRS that is created
    // from a ceremony. Everyone can attend and give their random value and if
    // only one person destroys their toxic waste, all of the SRS will be safe to use.
    let toxic_waste = Fr::random(rng);

    let (trusted_setup_g1, trusted_setup_g2, _) = (0..length).fold(
        (
            Vec::with_capacity(length),
            Vec::with_capacity(length),
            Fr::ONE,
        ),
        |(mut acc_g1, mut acc_g2, current_power), _| {
            acc_g1.push((generator_g1 * current_power).to_affine());
            acc_g2.push((generator_g2 * current_power).to_affine());

            // Update the power
            let next_power = current_power * toxic_waste;

            // Return the updated accumulator
            (acc_g1, acc_g2, next_power)
        },
    );

    SRSParams {
        g1: trusted_setup_g1,
        g2: trusted_setup_g2,
    }
}
