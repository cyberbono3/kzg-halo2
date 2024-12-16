use criterion::{criterion_group, criterion_main, Criterion};

use halo2_project::kzg::kzg::Proof;
use halo2_project::kzg::vector::tests::generate_test_data;
use halo2_project::kzg::vector::{prove, verify};

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
