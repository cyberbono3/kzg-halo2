use criterion::{criterion_group, criterion_main, Criterion};
use halo2::{halo2curves::bn256::Fr, arithmetic::Field};
use rand::thread_rng;

use halo2_project::kzg::vector::{prove, verify}; 
use halo2_project::kzg::kzg::Proof;
use halo2_project::srs::SRSParams;
use halo2_project::fr_vec;
use halo2_project::srs::trusted_setup_generator;

fn generate_test_data() -> (Vec<Fr>, Vec<Fr>, SRSParams) {
    let k = 100; // Power of tau for the SRS setup
    let params = trusted_setup_generator(k);

    let vector_size = 50; // Size of the input vector
   // let rng = &mut thread_rng();

    // Generate a random vector and challenge
    let vector: Vec<Fr> = (0..vector_size).map(|_| Fr::random( &mut thread_rng())).collect();
    let challenge: Vec<Fr> = fr_vec![0,1,2,3];

    (vector, challenge, params)
}

fn benchmark_vector_prove(c: &mut Criterion) {
    let (vector, challenge, params) = generate_test_data();

    c.bench_function("Prove Function", |b| {
        b.iter(|| {
            let _proof: Proof = prove(&vector, &challenge, &params);
        });
    });
}

fn benchmark_vector_verify(c: &mut Criterion) {
    let (vector, challenge, params) = generate_test_data();
    let proof = prove(&vector, &challenge, &params);

    c.bench_function("Verify Function", |b| {
        b.iter(|| {
            let result = verify(proof.clone(), &vector, &challenge, &params);
            assert!(result);
        });
    });
}

criterion_group!(benches, benchmark_vector_prove, benchmark_vector_verify);
criterion_main!(benches);
