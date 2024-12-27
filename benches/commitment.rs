use criterion::{criterion_group, criterion_main, Criterion};
use halo2_project::poly::Polynomial; // Adjust this import to your project structure
use halo2_project::srs::trusted_setup_generator;

fn benchmark_commitment_g1(c: &mut Criterion) {
    let k = 100; // Power of tau for SRS setup
    let params = trusted_setup_generator(k); // Generates the SRS
    let circuit_size = 50; // Degree of the polynomial
    let polynomial = Polynomial::random(circuit_size); // Generate a random polynomial

    c.bench_function("Commitment G1", |b| {
        b.iter(|| {
            let _ = polynomial.commitment_g1(&params.g1);
        })
    });
}

fn benchmark_commitment_g2(c: &mut Criterion) {
    let k = 100; // Power of tau for SRS setup
    let params = trusted_setup_generator(k); // Generates the SRS
    let circuit_size = 50; // Degree of the polynomial
    let polynomial = Polynomial::random(circuit_size); // Generate a random polynomial

    c.bench_function("Commitment G2", |b| {
        b.iter(|| {
            let _ = polynomial.commitment_g2(&params.g2);
        })
    });
}

criterion_group!(benches, benchmark_commitment_g1, benchmark_commitment_g2);
criterion_main!(benches);
