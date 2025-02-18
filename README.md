# KZG + Halo2 

[KZG polynomial commitment scheme](https://www.cypherpunks.ca/~iang/pubs/PolyCommit-AsiaCrypt.pdf) & [Halo2](https://github.com/zcash/halo2?tab=readme-ov-file)

*Note*: This is a free time project, not for production use.

# Usage

```rust
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
```
# Benchmarks 
```
cargo bench

Running benches/commitment.rs (target/release/deps/commitment-58dd98281bdfd285)
Commitment G1           time:   [9.1713 ms 9.1909 ms 9.2077 ms]
                        change: [-0.5986% -0.2991% +0.0105%] (p = 0.05 > 0.05)
                        No change in performance detected.
Found 3 outliers among 100 measurements (3.00%)
  3 (3.00%) low severe

Commitment G2           time:   [32.553 ms 32.654 ms 32.747 ms]
                        change: [-0.2832% +0.3285% +1.0530%] (p = 0.35 > 0.05)
                        No change in performance detected.
Found 9 outliers among 100 measurements (9.00%)
  3 (3.00%) low severe
  4 (4.00%) low mild
  2 (2.00%) high severe

     Running benches/kzg.rs (target/release/deps/kzg-967d7afd97a5820e)
KZG Prove               time:   [18.133 ms 18.216 ms 18.291 ms]
                        change: [-0.2160% +0.3162% +0.8533%] (p = 0.26 > 0.05)
                        No change in performance detected.
Found 16 outliers among 100 measurements (16.00%)
  7 (7.00%) low severe
  4 (4.00%) low mild
  5 (5.00%) high mild

KZG Verify              time:   [2.8904 ms 2.8971 ms 2.9030 ms]
                        change: [-0.3797% +0.2615% +0.9818%] (p = 0.47 > 0.05)
                        No change in performance detected.
Found 8 outliers among 100 measurements (8.00%)
  4 (4.00%) low severe
  1 (1.00%) low mild
  3 (3.00%) high mild

Running benches/kzg_vector.rs (target/release/deps/kzg_vector-a28f61ab14143a56)
Benchmarking Prove Function: Warming up for 3.0000 s
Warning: Unable to complete 100 samples in 5.0s. You may wish to increase target time to 7.5s, enable flat sampling, or reduce sample count to 50.
Prove Function          time:   [1.4899 ms 1.4947 ms 1.4991 ms]
                        change: [-1.2129% -0.4318% +0.2939%] (p = 0.26 > 0.05)
                        No change in performance detected.
Found 16 outliers among 100 measurements (16.00%)
  9 (9.00%) low severe
  3 (3.00%) low mild
  3 (3.00%) high mild
  1 (1.00%) high severe

Verify Function         time:   [5.8113 ms 5.8197 ms 5.8278 ms]
                        change: [+0.0387% +0.2714% +0.5293%] (p = 0.03 < 0.05)
                        Change within noise threshold.
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) low severe
  2 (2.00%) high mild
```
