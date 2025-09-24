use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::algorithms::allocate_and_generate_new_lwe_packing_keyswitch_key;
use refined_tfhe_lhe::{int_lhe_instance::*};
use refined_tfhe_lhe::{keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext_ms18};
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
        let mut plain2 = PlaintextList::new(0u64, PlaintextCount(CIPHERNUM));
        let step = polynomial_size.0 / CIPHERNUM;
        let mut plain_slice = plain.as_ref();
        let mut plain2_slice = plain2.as_mut();

        for i in 0..CIPHERNUM {
            let idx = step * i;
            plain2_slice[i] = plain_slice[i];
        }
        encrypt_lwe_ciphertext_list(
            &lwe_sk,
            &mut lwelist,
            &plain,
            glwe_modular_std_dev,
            &mut encryption_generator,
        );

        let mut glwe = GlweCiphertext::new(u64::ZERO, glwe_dimension.to_glwe_size(), polynomial_size, ciphertext_modulus);

        // 벤치마킹
        group.bench_function(
            BenchmarkId::new(
            format!("[CGGI16, MS18] Packing KS"), id
            ), |b| {
            b.iter(|| {
                keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext_ms18(
                    black_box(&pksk),
                    black_box(&lwelist),
                    black_box(&mut glwe),
                );

            });
        });

        group.bench_function(
            BenchmarkId::new(
            format!("TFHE-rs Version of CGGI16 Packing"), id
            ), |b| {
            b.iter(|| {

                keyswitch_lwe_ciphertext_list_and_pack_in_glwe_ciphertext(
                    black_box(&pksk),
                    black_box(&lwelist),
                    black_box(&mut glwe),
                );

            });
        });

    }
}

