use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::fft_impl::fft64::c64;
use refined_tfhe_lhe::{allocate_and_generate_new_glwe_keyswitch_key, convert_standard_glwe_keyswitch_key_to_fourier, glwe_preprocessing_assign, trace_assign_with_glwe_preprocess, revtrace_assign, get_glwe_avg_err, get_glwe_max_err, get_glwe_l2_err, trace_assign, blind_rotate_for_msb, convert_to_ggsw_after_blind_rotate, gen_all_auto_keys, get_max_err_ggsw_bit, glwe_ciphertext_clone_from, glwe_ciphertext_monic_monomial_div, keygen_pbs, int_lhe_instance::*};
use refined_tfhe_lhe::{glwe_conv::*, glwe_conv_rev::*, keyswitch_glwe_ciphertext};
use refined_tfhe_lhe::FourierGlweKeyswitchKey;
// use crate::{keyswitch_glwe_ciphertext, FourierGlweKeyswitchKey};
static sample_size:usize = 1000;
pub const CIPHERNUM: usize = 4;

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(sample_size);
    targets =
        criterion_benchmark_packlwes,
        criterion_benchmark_high_prec_packlwes,
        // criterion_benchmark_large_ring_auto,
);
criterion_main!(benches);

#[allow(unused)]
fn criterion_benchmark_packlwes(c: &mut Criterion) {
    let mut group = c.benchmark_group("PackLWEs");
    let param_list = [
        (*INT_LHE_BASE_64_REV, 1, "INT_LHE_BASE_64_REV PackLWEs"),
        (*INT_LHE_BASE_256_REV, 1, "INT_LHE_BASE_256_REV PackLWEs"),
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


    // Set input LWE ciphertext
    let msg = (1 << message_size) - 1;
    let mut lwelist = LweCiphertextList::new(0u64, bsk.output_lwe_dimension().to_lwe_size(), LweCiphertextCount(CIPHERNUM), ciphertext_modulus); 
    let plain = PlaintextList::from_container((0..CIPHERNUM).map(|i| {
        msg
    }).collect::<Vec<u64>>());
    let mut plain2 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
    let step = polynomial_size.0 / CIPHERNUM;
    let mut plain_slice = plain.as_ref();
    let mut plain2_slice = plain2.as_mut();

    for i in 0..CIPHERNUM {
        let idx = step * i;
        plain2_slice[idx] = plain_slice[i];
    }
    // encrypt_lwe_ciphertext_list(
    //     &lwe_sk,
    //     &mut lwelist,
    //     &plain,
    //     glwe_modular_std_dev,
    //     &mut encryption_generator,
    // );
    let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
    let mut l2_err = Vec::new();
    let mut max_err = Vec::new();
    let mut avg_err = Vec::new();
    
    group.bench_function(
        BenchmarkId::new(
            format!("Original PackLWEs"), id
        ),

        |b| {
            b.iter(|| {
                // let plain = PlaintextList::new(u64::ZERO, PlaintextCount(polynomial_size.0));
                encrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &mut lwelist,
                    &plain,
                    glwe_modular_std_dev,
                    &mut encryption_generator,
                );
                
                let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
                convert_lwes_to_glwe_by_trace_with_preprocessing(black_box(&lwelist), black_box(&mut glwe), black_box(&auto_keys));

                let err = get_glwe_l2_err(&glwe_sk, &glwe, &plain2);
                let err2 = get_glwe_max_err(&glwe_sk, &glwe, &plain2);
                let err3 = get_glwe_avg_err(&glwe_sk, &glwe, &plain2);
                l2_err.push(err);
                max_err.push(err2);
                avg_err.push(err3);
                black_box((err, err2, err3));

                // println!("[L2 Error of Original Trace function] {:.3} bits", (err as f64).log2());
                // println!("[Maximum Error of Original Trace function] {:.3} bits", (err2 as f64).log2());
                // println!("[Average Error of Original Trace function] {:.3} bits", (err3 as f64).log2());
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

    group.bench_function(
        BenchmarkId::new(
            format!("MS-PackLWEs"), id
        ),
        |b| {
            b.iter(|| {
                // let plain = PlaintextList::new(u64::ZERO, PlaintextCount(polynomial_size.0));
                encrypt_lwe_ciphertext_list(
                    &lwe_sk,
                    &mut lwelist,
                    &plain,
                    glwe_modular_std_dev,
                    &mut encryption_generator,
                );
                
                // let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
                convert_lwes_to_glwe_by_revtrace(black_box(&lwelist), black_box(&mut glwe), black_box(&auto_keys));

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
    println!("[L2 Error of RevHom PackLWEs] {:.3} bits", ((l2_avg2 as f64)).log2());
    println!("[Maximum Error of RevHom PackLWEs] {:.3} bits", ((max_avg2 as f64)).log2());
    println!("[Average Error of RevHom PackLWEs] {:.3} bits", ((avg_avg2 as f64)).log2());


        println!(
            "N: {}, k: {}, l_tr: {}, B_tr: 2^{},",
            polynomial_size.0, glwe_dimension.0, auto_level.0, auto_base_log.0
        );

}
}

// criterion_group!(benches, bench_trace_operation);
// criterion_main!(benches);


#[allow(unused)]
fn criterion_benchmark_high_prec_packlwes(c: &mut Criterion) {
    let mut group = c.benchmark_group("PackLWEs");

    let param_list = [
        (*INT_LHE_BASE_64, 1, "INT_LHE_BASE_64 HighPrec PackLWEs"),
        (*INT_LHE_BASE_256, 1, "INT_LHE_BASE_256 HighPrec PackLWEs"),
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

        let msg = (1 << message_size) - 1;
        let mut lwelist = LweCiphertextList::new(0u64, bsk.output_lwe_dimension().to_lwe_size(), LweCiphertextCount(CIPHERNUM), ciphertext_modulus); 
        let plain = PlaintextList::from_container((0..CIPHERNUM).map(|i| {
            msg
        }).collect::<Vec<u64>>());
        let mut plain2 = PlaintextList::new(0u64, PlaintextCount(polynomial_size.0));
        let step = polynomial_size.0 / CIPHERNUM;
        let mut plain_slice = plain.as_ref();
        let mut plain2_slice = plain2.as_mut();

        for i in 0..CIPHERNUM {
            let idx = step * i;
            plain2_slice[idx] = plain_slice[i];
    }
        encrypt_lwe_ciphertext_list(
            &lwe_sk,
            &mut lwelist,
            &plain,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );
        let mut glwe_out = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

        let mut l2_err3 = Vec::new();
        let mut max_err3 = Vec::new();
        let mut avg_err3 = Vec::new();

        group.bench_function(
            BenchmarkId::new(
                format!("High Precision PackLWEs"), id
            ),
    
            |b| {
                b.iter(|| {
                    let mut glwe_out = GlweCiphertext::new(u64::ZERO, glwe_size, polynomial_size, ciphertext_modulus);
                    encrypt_lwe_ciphertext_list(
                        &lwe_sk,
                        &mut lwelist,
                        &plain,
                        glwe_modular_std_dev,
                        &mut encryption_generator,
                    );
                    // convert_lwes_to_glwe_by_revtrace(&lwelist, &mut glwe_out, &auto_keys);
                    convert_lwes_to_glwe_by_trace_with_preprocessing_high_prec(
                        black_box(&lwelist),
                        black_box(&mut glwe_out), 
                        black_box(&fourier_glwe_ksk_to_large), 
                        black_box(&fourier_glwe_ksk_from_large), 
                        black_box(&auto_keys),
                    );
    
                    let err = get_glwe_l2_err(&glwe_sk, &glwe_out, &plain2);
                    let err2 = get_glwe_max_err(&glwe_sk, &glwe_out, &plain2);
                    let err3 = get_glwe_avg_err(&glwe_sk, &glwe_out, &plain2);
                    l2_err3.push(err);
                    max_err3.push(err2);
                    avg_err3.push(err3);
                    black_box((err, err2, err3));
    
                    // println!("[L2 Error of Original Trace function] {:.3} bits", (err as f64).log2());
                    // println!("[Maximum Error of Original Trace function] {:.3} bits", (err2 as f64).log2());
                    // println!("[Average Error of Original Trace function] {:.3} bits", (err3 as f64).log2());
                });
        });
        let l2_avg3 = l2_err3.iter().sum::<f64>() / l2_err3.len() as f64;
        let max_avg3 = (max_err3.iter().sum::<u64>() as f64)/ max_err3.len() as f64;
        let avg_avg3 = avg_err3.iter().sum::<f64>() / avg_err3.len() as f64;
        println!("[L2 Error of HP-Trace PackLWEs] {:.3} bits", ((l2_avg3 as f64)).log2());
        println!("[Maximum Error of HP-Trace PackLWEs] {:.3} bits", ((max_avg3 as f64)).log2());
        println!("[Average Error of HP-Trace PackLWEs] {:.3} bits", ((avg_avg3 as f64)).log2());
    }


}



