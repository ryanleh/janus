use criterion::{criterion_group, criterion_main, Criterion};
use itertools::iproduct;
use janus_core::{
    hpke::{self, HpkeApplicationInfo, Label, HpkeKeypair},
    vdaf::vdaf_application_context,
    test_util::run_vdaf,
};
use janus_messages::{
    ReportId, ReportMetadata, Role, TaskId, Time, PlaintextInputShare, InputShareAad,
};
use prio::vdaf::{prio3::{Prio3SumVec, optimal_chunk_length}, Vdaf};
use prio::topology::ping_pong::PingPongTopology;
use janus_messages::codec::{Decode, Encode, ParameterizedDecode};
use std::hint::black_box;

fn bench_vdaf(c: &mut Criterion, input_length: usize, bitwidth: usize) {
    // Setup metadata
    let task_id = TaskId::from([1u8; 32]);
    let report_id = ReportId::from([2u8; 16]);
    let report_metadata = ReportMetadata::new(
        report_id,
        Time::from_seconds_since_epoch(1_000_000_000),
        vec![], // No public extensions
    );

    // Create VDAF instance with the specified parameters
    // For Prio3SumVec, the parameters are: (num_shares, bits, length, chunk_length)
    let chunk_length = optimal_chunk_length(input_length * bitwidth);
    let vdaf = Prio3SumVec::new_sum_vec(2, bitwidth, input_length, chunk_length).unwrap();
    let verify_key = [3u8; 32]; // 32 bytes for libprio 0.17.0
    let aggregation_param = (); // Unit type for Prio3SumVec

    // Create measurement with the correct format for this VDAF instance
    // Each measurement is a vector of length 'input_length', with each element fitting within 'bitwidth' bits
    let measurement = (0..input_length)
        .map(|_| 1u128 >> (128 - bitwidth))
        .collect::<Vec<_>>();

    // Use the library's test utility to generate a complete VDAF transcript
    // This includes properly constructed input shares, proofs, and all VDAF state
    let transcript = run_vdaf(
        &vdaf,
        &task_id,
        &verify_key,
        &aggregation_param,
        &report_id,
        &measurement,
    );

    // Create HPKE keypair for encryption/decryption
    let hpke_keypair = HpkeKeypair::test();
    let hpke_config = hpke_keypair.config().clone();

    // Use the library's test utility to generate a proper report share
    // This handles all the encryption and encoding correctly
    let report_share = janus_aggregator::aggregator::test_util::generate_helper_report_share::<Prio3SumVec>(
        task_id,
        report_metadata.clone(),
        &hpke_config,
        &transcript.public_share,
        vec![], // No private extensions
        &transcript.helper_input_share,
    );

    // Reconstruct the AAD that was used during encryption
    let input_share_aad = InputShareAad::new(
        task_id,
        report_metadata.clone(),
        report_share.public_share().to_vec(),
    );

    let group_name = format!("prio3/{}_inputs_{}_bits", input_length, bitwidth);
    
    c.benchmark_group(&group_name)
        .bench_function("decrypt_and_decode", |b| {
            b.iter(|| {
                // Complete decoding workflow: HPKE + PlaintextInputShare + InputShare + PublicShare
                // This represents the full decoding overhead from aggregation_job_init.rs
                
                // Step 1: HPKE Decryption
                let plaintext = hpke::open(
                    &hpke_keypair,
                    &HpkeApplicationInfo::new(&Label::InputShare, &Role::Client, &Role::Helper),
                    report_share.encrypted_input_share(),
                    &input_share_aad.get_encoded().unwrap(),
                ).unwrap();

                // Step 2: Decode PlaintextInputShare
                let plaintext_input_share = PlaintextInputShare::get_decoded(&plaintext).unwrap();
                
                // Step 3: Decode InputShare
                let input_share = <Prio3SumVec as Vdaf>::InputShare::get_decoded_with_param(
                    &(&vdaf, Role::Helper.index().unwrap()),
                    plaintext_input_share.payload(),
                ).unwrap();
                
                // Step 4: Decode PublicShare
                let public_share = <Prio3SumVec as Vdaf>::PublicShare::get_decoded_with_param(
                    &vdaf,
                    report_share.public_share(),
                ).unwrap();
                
                // Return all decoded components to prevent optimization
                black_box((plaintext_input_share, input_share, public_share))
            });
        })
        .bench_function("verify_leader", |b| {
            // Benchmark leader verification only - process only leader's transitions
            let ctx = vdaf_application_context(&task_id);
 
            b.iter(|| {
                // Step 1: Leader initialization
                black_box(vdaf.leader_initialized(
                    &verify_key,
                    &ctx,
                    &aggregation_param,
                    report_id.as_ref(),
                    &transcript.public_share,
                    &transcript.leader_input_share,
                ).unwrap());
                
                // Step 2: Process only leader's transitions (skip first one as it's initialization)
                for leader_transition in transcript.leader_prepare_transitions.iter().skip(1) {
                    if let Some(continuation) = &leader_transition.continuation {
                        let _ping_pong_state = continuation.evaluate(&ctx, &vdaf).unwrap();
                    }
                }
                
                // Return the leader output share to prevent optimization
                black_box(&transcript.leader_output_share)
            });
        })
        .bench_function("verify_helper", |b| {
            // Benchmark helper verification only - process only helper's transitions
            let ctx = vdaf_application_context(&task_id);

            // Step 1: Helper initialization (needs leader's first message)
            let leader_state = vdaf.leader_initialized(
                &verify_key,
                &ctx,
                &aggregation_param,
                report_id.as_ref(),
                &transcript.public_share,
                &transcript.leader_input_share,
            ).unwrap();
                
            b.iter(|| {
                let helper_continuation = vdaf.helper_initialized(
                    &verify_key,
                    &ctx,
                    &aggregation_param,
                    report_id.as_ref(),
                    &transcript.public_share,
                    &transcript.helper_input_share,
                    &leader_state.message,
                ).unwrap();
                let _helper_state = helper_continuation.evaluate(&ctx, &vdaf).unwrap();
                
                // Step 2: Process only helper's transitions (skip first one as it's initialization)
                for helper_transition in transcript.helper_prepare_transitions.iter().skip(1) {
                    if let Some(continuation) = &helper_transition.continuation {
                        let _ping_pong_state = continuation.evaluate(&ctx, &vdaf).unwrap();
                    }
                }
                
                // Return the helper output share to prevent optimization
                black_box(&transcript.helper_output_share)
            });
        });
}

fn run_benches(c: &mut Criterion) {
    let length = vec![1, 8, 16, 64, 128];
    let bitwidth = vec![1, 8];

    for (l, b) in iproduct!(&length, &bitwidth) {
        let chunk_length = optimal_chunk_length(l * b);
        println!("Input length: {}, Bitwidth: {}, Chunk length: {}", l, b, chunk_length);
        bench_vdaf(c, *l, *b);
    }
}

criterion_group!(benches, run_benches);
criterion_main!(benches); 
