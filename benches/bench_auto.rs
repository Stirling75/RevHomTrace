use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::fft_impl::fft64::c64;
use refined_tfhe_lhe::{mod_switch_rev::*, glwe_conv_rev::*, allocate_and_generate_new_glwe_keyswitch_key, convert_standard_glwe_keyswitch_key_to_fourier, glwe_preprocessing_assign, trace_assign_with_glwe_preprocess, revtrace_assign, get_glwe_avg_err, get_glwe_max_err, get_glwe_l2_err, trace_assign, blind_rotate_for_msb, convert_to_ggsw_after_blind_rotate, convert_to_ggsw_after_blind_rotate_revtrace, gen_all_auto_keys, generate_scheme_switching_key, get_max_err_ggsw_bit, glwe_ciphertext_clone_from, glwe_ciphertext_monic_monomial_div, keygen_pbs, int_lhe_instance::*};
use refined_tfhe_lhe::{keyswitch_glwe_ciphertext};
use refined_tfhe_lhe::FourierGlweKeyswitchKey;
// use crate::{keyswitch_glwe_ciphertext, FourierGlweKeyswitchKey};

static sample_size:usize = 1000;


criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(sample_size);
    targets =
        criterion_benchmark_auto,
        criterion_benchmark_high_prec_auto,
        // criterion_benchmark_large_ring_auto,
);
criterion_main!(benches);

#[allow(unused)]
fn criterion_benchmark_auto(c: &mut Criterion) {
    let mut group = c.benchmark_group("GLWE_TRACE");
    let param_list = [
        (*INT_LHE_BASE_64_REV, 1, "INT_LHE_BASE_64_REV Trace"),
        (*INT_LHE_BASE_256_REV, 1, "INT_LHE_BASE_256_REV Trace"),
    ];

    for (param, extract_size, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let glwe_dimension = param.glwe_dimension();
        let polynomial_size = param.polynomial_size();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
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

        let extract_size = *extract_size;
        let glwe_size = glwe_dimension.to_glwe_size();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_sk,
            glwe_sk,
            lwe_sk_after_ks,
            bsk,
            ksk,
        ) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let bsk = bsk.as_view();

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &lwe_sk,
            &lwe_sk_after_ks,
            ks_base_log,
            ks_level,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            auto_fft_type,
            &glwe_sk,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let ss_key = generate_scheme_switching_key(
            &glwe_sk,
            ss_base_log,
            ss_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let ss_key = ss_key.as_view();



    group.bench_function(
        BenchmarkId::new(
            format!("Original Trace Function"), id
        ),

        |b| {
            let plain = PlaintextList::new(u64::ZERO, PlaintextCount(polynomial_size.0));
            let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
            encrypt_glwe_ciphertext(&glwe_sk, &mut glwe, &plain, glwe_modular_std_dev, &mut encryption_generator);
            let mut ct = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
            glwe_ciphertext_clone_from(&mut ct, &glwe);
            b.iter(|| {
                glwe_preprocessing_assign(black_box(&mut glwe));
                trace_assign(black_box(&mut glwe), black_box(&auto_keys));
            });
    });

    group.bench_function(
        BenchmarkId::new(
            format!("RevHomTrace Function"), id
        ),

        |b| {
            let plain = PlaintextList::new(u64::ZERO, PlaintextCount(polynomial_size.0));
            let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
            encrypt_glwe_ciphertext(&glwe_sk, &mut glwe, &plain, glwe_modular_std_dev, &mut encryption_generator);
            b.iter(|| {

                revtrace_assign(black_box(&mut glwe), black_box(&auto_keys));
            });
    });
}
}



#[allow(unused)]
fn criterion_benchmark_high_prec_auto(c: &mut Criterion) {
    let mut group = c.benchmark_group("wopbs");

    let param_list = [
        (*INT_LHE_BASE_64, 1, "INT_LHE_BASE_64 HighPrec Trace"),
        (*INT_LHE_BASE_256, 1, "INT_LHE_BASE_256 HighPrec Trace"),
    ];
    
    for (param, extract_size, id) in param_list.iter() {
        let lwe_dimension = param.lwe_dimension();
        let lwe_modular_std_dev = param.lwe_modular_std_dev();
        let polynomial_size = param.polynomial_size();
        let glwe_dimension = param.glwe_dimension();
        let glwe_modular_std_dev = param.glwe_modular_std_dev();
        let large_glwe_dimension = param.large_glwe_dimension();
        let large_glwe_modular_std_dev = param.large_glwe_modular_std_dev();
        let pbs_base_log = param.pbs_base_log();
        let pbs_level = param.pbs_level();
        let ks_base_log = param.ks_base_log();
        let ks_level = param.ks_level();
        let glwe_ds_to_large_base_log = param.glwe_ds_to_large_base_log();
        let glwe_ds_to_large_level = param.glwe_ds_to_large_level();
        let fft_type_to_large = param.fft_type_to_large();
        let glwe_ds_from_large_base_log = param.glwe_ds_from_large_base_log();
        let glwe_ds_from_large_level = param.glwe_ds_from_large_level();
        let fft_type_from_large = param.fft_type_from_large();
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

        let extract_size = *extract_size;
        let glwe_size = glwe_dimension.to_glwe_size();
        let large_glwe_size = large_glwe_dimension.to_glwe_size();

        // Set random generators and buffers
        let mut boxed_seeder = new_seeder();
        let seeder = boxed_seeder.as_mut();

        let mut secret_generator = SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        let mut encryption_generator = EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        // Generate keys
        let (
            lwe_sk,
            glwe_sk,
            lwe_sk_after_ks,
            bsk,
            ksk,
        ) = keygen_pbs(
            lwe_dimension,
            glwe_dimension,
            polynomial_size,
            lwe_modular_std_dev,
            glwe_modular_std_dev,
            pbs_base_log,
            pbs_level,
            ks_base_log,
            ks_level,
            &mut secret_generator,
            &mut encryption_generator,
        );
        let bsk = bsk.as_view();

        let ksk = allocate_and_generate_new_lwe_keyswitch_key(
            &lwe_sk,
            &lwe_sk_after_ks,
            ks_base_log,
            ks_level,
            lwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );

        let large_glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(large_glwe_dimension, polynomial_size, &mut secret_generator);

        let glwe_ksk_to_large = allocate_and_generate_new_glwe_keyswitch_key(
            &glwe_sk,
            &large_glwe_sk,
            glwe_ds_to_large_base_log,
            glwe_ds_to_large_level,
            large_glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut fourier_glwe_ksk_to_large = FourierGlweKeyswitchKey::new(
            glwe_size,
            large_glwe_size,
            polynomial_size,
            glwe_ds_to_large_base_log,
            glwe_ds_to_large_level,
            fft_type_to_large,
        );
        convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_to_large, &mut fourier_glwe_ksk_to_large);

        let glwe_ksk_from_large = allocate_and_generate_new_glwe_keyswitch_key(
            &large_glwe_sk,
            &glwe_sk,
            glwe_ds_from_large_base_log,
            glwe_ds_from_large_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let mut fourier_glwe_ksk_from_large = FourierGlweKeyswitchKey::new(
            large_glwe_size,
            glwe_size,
            polynomial_size,
            glwe_ds_from_large_base_log,
            glwe_ds_from_large_level,
            fft_type_from_large,
        );
        convert_standard_glwe_keyswitch_key_to_fourier(&glwe_ksk_from_large, &mut fourier_glwe_ksk_from_large);

        let auto_keys = gen_all_auto_keys(
            auto_base_log,
            auto_level,
            auto_fft_type,
            &large_glwe_sk,
            large_glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let ss_key = generate_scheme_switching_key(
            &glwe_sk,
            ss_base_log,
            ss_level,
            glwe_modular_std_dev,
            ciphertext_modulus,
            &mut encryption_generator,
        );
        let ss_key = ss_key.as_view();

        group.bench_function(
            BenchmarkId::new(
                format!("High Precision Trace Function"), id
            ),
    
            |b| {

                let plain = PlaintextList::new(u64::ZERO, PlaintextCount(polynomial_size.0));
                let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
                let mut glwe_out = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
                let mut buf_large_glwe = GlweCiphertext::new(u64::ZERO, fourier_glwe_ksk_to_large.output_glwe_size(), polynomial_size, ciphertext_modulus);
                encrypt_glwe_ciphertext(&glwe_sk, &mut glwe, &plain, glwe_modular_std_dev, &mut encryption_generator);

                b.iter(|| {

                    keyswitch_glwe_ciphertext(&fourier_glwe_ksk_to_large, &glwe, &mut buf_large_glwe);
                    glwe_preprocessing_assign(&mut buf_large_glwe);
                    trace_assign(&mut buf_large_glwe, &auto_keys);
                    keyswitch_glwe_ciphertext(&fourier_glwe_ksk_from_large, &buf_large_glwe, &mut glwe_out);

                });
        });

    }


}

