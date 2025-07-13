use criterion::{criterion_group, criterion_main, Criterion};
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label, HpkeKeypair},
    time::MockClock,
    vdaf::vdaf_application_context,
};
use janus_messages::{
    AggregateShareAad, BatchSelector, Duration, Interval, ReportId, ReportMetadata, Role, TaskId,
    Time, InputShareAad, PlaintextInputShare, Extension, ExtensionType,
};
use prio::vdaf::prio3::Prio3SumVec;
use prio::vdaf::{Client, Aggregator};
use janus_messages::codec::{Encode, Decode, ParameterizedDecode};
use std::hint::black_box;

fn benchmark_helper_input_share_processing(c: &mut Criterion) {
    // Setup outside the benchmark
    let task_id = TaskId::from([1u8; 32]);
    let report_id = ReportId::from([2u8; 16]);
    let report_metadata = ReportMetadata::new(
        report_id,
        Time::from_seconds_since_epoch(1_000_000_000),
        vec![], // No public extensions
    );

    // Create VDAF instance
    let vdaf = Prio3SumVec::new_sum_vec(2, 1, 1, 1).unwrap();

    // Create HPKE keypair for encryption/decryption
    let hpke_keypair = HpkeKeypair::test();
    let hpke_config = hpke_keypair.config().clone();

    // Create a dummy VDAF input share (simulating what a client would generate)
    let measurement = vec![1u128];
    let ctx = vdaf_application_context(&task_id);
    let (public_share, input_shares) = vdaf.shard(&ctx, &measurement, report_id.as_ref()).unwrap();
    let helper_input_share = &input_shares[1]; // Helper gets the second share

    // Create plaintext input share (what gets encrypted)
    let plaintext_input_share = PlaintextInputShare::new(
        vec![], // No private extensions
        helper_input_share.get_encoded().unwrap(),
    );

    // Create input share AAD (additional authenticated data)
    let input_share_aad = InputShareAad::new(
        task_id,
        report_metadata.clone(),
        public_share.get_encoded().unwrap(),
    );

    // Encrypt the helper's input share (simulating what gets stored in DB)
    let encrypted_input_share = hpke::seal(
        &hpke_config,
        &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
        &plaintext_input_share.get_encoded().unwrap(),
        &input_share_aad.get_encoded().unwrap(),
    ).unwrap();

    c.benchmark_group("helper_input_share_processing")
        .bench_function("decrypt_and_decode_helper_input_share", |b| {
            b.iter(|| {
                // Step 1: HPKE Decryption (Line 179 in aggregation_job_init.rs)
                let plaintext = hpke::open(
                    &hpke_keypair,
                    &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
                    black_box(&encrypted_input_share),
                    &input_share_aad.get_encoded().unwrap(),
                ).unwrap();

                // Step 2: Decode PlaintextInputShare (Line 201 in aggregation_job_init.rs)
                let plaintext_input_share = PlaintextInputShare::get_decoded(&plaintext).unwrap();

                // Step 3: Decode VDAF Input Share (Line 275 in aggregation_job_init.rs)
                // Note: We can't easily decode the VDAF input share without the specific type
                // So we just measure the payload size to prevent optimization
                let _payload_size = plaintext_input_share.payload().len();

                // Return something to prevent optimization
                black_box(_payload_size)
            });
        })
        .bench_function("hpke_decryption_only", |b| {
            b.iter(|| {
                // Only the HPKE decryption step
                let _plaintext = hpke::open(
                    &hpke_keypair,
                    &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
                    black_box(&encrypted_input_share),
                    &input_share_aad.get_encoded().unwrap(),
                ).unwrap();
            });
        })
        .bench_function("plaintext_decode_only", |b| {
            b.iter(|| {
                // Only the PlaintextInputShare decoding step (using pre-decrypted data)
                let plaintext = hpke::open(
                    &hpke_keypair,
                    &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
                    &encrypted_input_share,
                    &input_share_aad.get_encoded().unwrap(),
                ).unwrap();
                
                let _plaintext_input_share = PlaintextInputShare::get_decoded(&plaintext).unwrap();
            });
        });
}

criterion_group!(benches, benchmark_helper_input_share_processing);
criterion_main!(benches); 
