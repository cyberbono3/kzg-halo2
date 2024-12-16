use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2::halo2curves::bn256::Fr;
use rand::thread_rng;

use halo2_project::poly::Polynomial;
use halo2_project::srs::trusted_setup_generator;
use halo2_project::kzg::kzg::{prove, verify};

fn benchmark_prove(c: &mut Criterion) {
    let k = 100;
    let params = trusted_setup_generator(k);

    let circuit_size = 50;
    let polynomial = Polynomial::random(circuit_size);

    let rng = &mut thread_rng();
    let challenge = Fr::random(rng);

    c.bench_function("KZG Prove", |b| {
        b.iter(|| {
            // Benchmarking the `prove` function
            let proof = prove(black_box(polynomial.clone()), black_box(challenge), black_box(&params));
            black_box(proof);
        })
    });
}

fn benchmark_verify(c: &mut Criterion) {
    let k = 100;
    let params = trusted_setup_generator(k);

    let circuit_size = 50;
    let polynomial = Polynomial::random(circuit_size);

    let rng = &mut thread_rng();
    let challenge = Fr::random(rng);

    let proof = prove(polynomial, challenge, &params);

    c.bench_function("KZG Verify", |b| {
        b.iter(|| {
            // Benchmarking the `verify` function
            let res = verify(black_box(proof.clone()), black_box(challenge), black_box(&params));
            black_box(res);
        })
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    benchmark_prove(c);
    benchmark_verify(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);