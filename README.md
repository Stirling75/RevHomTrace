# Homomorphic Field Trace Revisited : Breaking the Cubic Noise Barrier
This is an implementation of '[**Homomorphic Field Trace Revisited : Breaking the Cubic Noise Barrier**'](https://eprint.iacr.org/2025/1088), built upon the implementation of '[Refined TFHE Leveled Homomorphic Evaluation and Its Application](https://eprint.iacr.org/2024/1318)', licensed under the MIT license. 

## Original Work Attribution
- **Original Repository**: https://github.com/KAIST-CryptLab/refined-tfhe-lhe
- **Original License**: MIT License
- **Original Copyright**: Copyright (c) 2024 KAIST-CryptLab

## Contents 
We extended the original library by implementing
- **RevHomTrace Algorithm** [automorphism_rev.rs](src/automorphism_rev.rs) with 1bit modulus switching in [mod_switch_rev.rs](src/mod_switch_rev.rs)
- **CBS (Circuit Bootstrapping) with RevHomTrace** [ggsw_conv_rev.rs](src/ggsw_conv_rev.rs)
- **LWEs-to-GLWE packing** algorithms via EvalAuto (MS-PackLWEs, HP-PackLWEs) [glwe_conv_rev.rs](src/glwe_conv_rev.rs)
- **CGGI16, MS18 Packing KS** [lwe_to_glwe.rs](src/lwe_to_glwe.rs)

We implemented benchmarks for:
- **Comparison between three different automorphism algorithms** (PreHomTrace (Sec. 3.2.2, Alg 3), RevHomTrace (Sec. 4), HP-HomTrace (Sec. 3.2.2, Alg 4)), for experimental results in Section 5.1
  - Latency [bench_auto.rs](benches/bench_auto.rs)
  - Error Comparison [bench_auto_err.rs](benches/bench_auto_err.rs)
- **Comparison between High Precision CBS**, for experimental results in Section 5.2
  - [bench_integer_input_lhe.rs](benches/bench_integer_input_lhe.rs)
- **Comparison between Packing LWEs-to-GLWE algorithms** (PackLWEs, MS-PackLWEs, HP-PackLWEs), for experimental results in Section 5.3
  - Latency [bench_ks.rs](benches/bench_ks.rs)
  - Error Comparison [bench_ks_err.rs](benches/bench_ks_err.rs)

- **Additional code for Packing LWEs-to-GLWE** with traditional packing KS (**PackKS, PackKS-rs**), for experimental results in Section 5.3
  - Latency [bench_tradks.rs](benches/bench_tradks.rs)
  - Error Comparison [bench_tradks_err.rs](benches/bench_tradks_err.rs)

## How to Use
All of the benchmarks are placed in **benches** directory. To run them, use the following command:
- bench: `cargo bench --bench 'benchmark_name'`
  - Example: '**cargo bench --bench bench_auto**'
  - Current sample size is set to 1000. 

## Environment
- This PoC Implementation has been tested on following environments:
  - Ubuntu 24.04, rustc version **1.86.0**
  - MacOS Sequoia & Tahoe, rustc version **1.89.0**
  
Also, there has been a report on crash while running this implementation with rustc version **1.75.0**. 
It is recommended to run this implementation with rustc version **> 1.86.0**