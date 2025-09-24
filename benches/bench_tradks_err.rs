use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::fft_impl::fft64::c64;
use tfhe::core_crypto::entities::LwePackingKeyswitchKey;
use tfhe::core_crypto::algorithms::allocate_and_generate_new_lwe_packing_keyswitch_key;
use refined_tfhe_lhe::{keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext_ms18};
use tfhe::core_crypto::algorithms::keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext;
use refined_tfhe_lhe::{allocate_and_generate_new_glwe_keyswitch_key, convert_standard_glwe_keyswitch_key_to_fourier, glwe_preprocessing_assign, trace_assign_with_glwe_preprocess, revtrace_assign, get_glwe_avg_err, get_glwe_max_err, get_glwe_l2_err, trace_assign, blind_rotate_for_msb, convert_to_ggsw_after_blind_rotate, gen_all_auto_keys, get_max_err_ggsw_bit, glwe_ciphertext_clone_from, glwe_ciphertext_monic_monomial_div, keygen_pbs, int_lhe_instance::*};
use refined_tfhe_lhe::{glwe_conv::*, glwe_conv_rev::*, keyswitch_glwe_ciphertext};
use refined_tfhe_lhe::FourierGlweKeyswitchKey;
// use crate::{keyswitch_glwe_ciphertext, FourierGlweKeyswitchKey};
static sample_size:usize = 1000;
pub const CIPHERNUM: usize = 2048;

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(sample_size);
    targets =
        criterion_benchmark_packing_ks,
);
criterion_main!(benches);

#[allow(unused)]
fn criterion_benchmark_packing_ks(c: &mut Criterion) {
    let mut group = c.benchmark_group("Packing KS");
    let param_list = [
    (*INT_LHE_BASE_64_REV, 1, "INT_LHE_BASE_64_REV"),
    (*INT_LHE_BASE_256_REV, 1, "INT_LHE_BASE_256_REV"),
    ];

    for (param, extract_size, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let glwe_dimension = param.glwe_dimension();
        let polynomial_size = param.polynomial_size();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.auto_base_log();         // Modified
        let ks_level = param.auto_level();               // Modified
        let auto_base_log = param.auto_base_log();
        let auto_level = param.auto_level();
        let auto_fft_type = param.fft_type_auto();
        let ss_base_log = param.ss_base_log();
        let ss_level = param.ss_level();
        let cbs_base_log = param.cbs_base_log();
        let cbs_level = param.cbs_level();
        let log_lut_count = param.log_lut_count();
        let ciphertext_modulus = param.ciphertext_modulus();
        let message_size = param.message_size();
        

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut secret_gen = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);


        let lwe_sk  = allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_gen);
        let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(glwe_dimension, polynomial_size, &mut secret_gen);
        let pksk = allocate_and_generate_new_lwe_packing_keyswitch_key(
            &lwe_sk,
            &glwe_sk,
            ks_base_log,
            ks_level,
            param.glwe_modular_std_dev(),
            ciphertext_modulus,
            &mut encryption_generator,
        );


        let msg = (1 << message_size) - 2;
        let mut lwelist = LweCiphertextList::new(0u64, lwe_dimension.to_lwe_size(), LweCiphertextCount(CIPHERNUM), ciphertext_modulus); 
        let plain = PlaintextList::from_container((0..CIPHERNUM).map(|i| {
            msg
        }).collect::<Vec<u64>>());
        let mut plain2 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        let step = polynomial_size.0 / CIPHERNUM;
        let mut plain_slice = plain.as_ref();
        let mut plain2_slice = plain2.as_mut();

        for i in 0..CIPHERNUM {
            let idx = step * i;
            plain2_slice[i] = plain_slice[i];
        }
        // encrypt_lwe_ciphertext_list(
        //     &lwe_sk,
        //     &mut lwelist,
        //     &plain,
        //     glwe_modular_std_dev,
        //     &mut encryption_generator,
        // );
        let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_dimension.to_glwe_size(), polynomial_size, ciphertext_modulus);
        let mut l2_err = Vec::new();
        let mut max_err = Vec::new();
        let mut avg_err = Vec::new();
        

        // 벤치마킹
        group.bench_function(
            BenchmarkId::new(
            format!("[CGGI16, MS18] Packing KS"), id
            ), |b| {
            b.iter(|| {
                // let plain = PlaintextList::new(u64::ZERO, PlaintextCount(polynomial_size.0));
                encrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &mut lwelist,
                    &plain,
                    glwe_modular_std_dev,
                    &mut encryption_generator,
                );
                keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext_ms18(
                    black_box(&pksk),
                    black_box(&lwelist),
                    black_box(&mut glwe),
                );
                let err = get_glwe_l2_err(&glwe_sk, &glwe, &plain2);
                let err2 = get_glwe_max_err(&glwe_sk, &glwe, &plain2);
                let err3 = get_glwe_avg_err(&glwe_sk, &glwe, &plain2);
                l2_err.push(err);
                max_err.push(err2);
                avg_err.push(err3);
                black_box((err, err2, err3));
            });
        });
        let l2_avg = l2_err.iter().sum::<f64>() / l2_err.len() as f64;
        let max_avg = (max_err.iter().sum::<u64>() as f64)/ max_err.len() as f64;
        let avg_avg = avg_err.iter().sum::<f64>() / avg_err.len() as f64;
        println!("[L2 Error of Original PackLWEs] {:.3} bits", ((l2_avg as f64)).log2());
        println!("[Maximum Error of Original PackLWEs] {:.3} bits", ((max_avg as f64)).log2());
        println!("[Average Error of Original PackLWEs] {:.3} bits", ((avg_avg as f64)).log2());

        let mut l2_err2 = Vec::new();
        let mut max_err2 = Vec::new();
        let mut avg_err2 = Vec::new();
        

        // 벤치마킹
        group.bench_function(
            BenchmarkId::new(
            format!("TFHE-rs Version of CGGI16 Packing"), id
            ), |b| {
            b.iter(|| {
                // let plain = PlaintextList::new(u64::ZERO, PlaintextCount(polynomial_size.0));
                encrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &mut lwelist,
                    &plain,
                    glwe_modular_std_dev,
                    &mut encryption_generator,
                );
                keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                    black_box(&pksk),
                    black_box(&lwelist),
                    black_box(&mut glwe),
                );
                let err = get_glwe_l2_err(&glwe_sk, &glwe, &plain2);
                let err2 = get_glwe_max_err(&glwe_sk, &glwe, &plain2);
                let err3 = get_glwe_avg_err(&glwe_sk, &glwe, &plain2);
                l2_err2.push(err);
                max_err2.push(err2);
                avg_err2.push(err3);
                black_box((err, err2, err3));
            });
        });
        let l2_avg2 = l2_err2.iter().sum::<f64>() / l2_err2.len() as f64;
        let max_avg2 = (max_err2.iter().sum::<u64>() as f64)/ max_err2.len() as f64;
        let avg_avg2 = avg_err2.iter().sum::<f64>() / avg_err2.len() as f64;
        println!("[L2 Error of Original PackLWEs] {:.3} bits", ((l2_avg2 as f64)).log2());
        println!("[Maximum Error of Original PackLWEs] {:.3} bits", ((max_avg2 as f64)).log2());
        println!("[Average Error of Original PackLWEs] {:.3} bits", ((avg_avg2 as f64)).log2());

        // group.finish();
    }
}

