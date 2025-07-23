use janus_core::{
    test_util::run_vdaf,
};
use janus_messages::{
    ReportId, ReportMetadata, TaskId, Time,
};
use itertools::iproduct;
use janus_messages::codec::Encode;
use prio::vdaf::prio3::{Prio3SumVec, optimal_chunk_length};
use std::collections::HashMap;

#[derive(Debug)]
struct NetworkMessages {
    client_upload: HashMap<String, f64>,
    server_to_server: HashMap<String, f64>,
    collection: HashMap<String, f64>,
    total: f64,
}

impl NetworkMessages {
    fn new() -> Self {
        Self {
            client_upload: HashMap::new(),
            server_to_server: HashMap::new(),
            collection: HashMap::new(),
            total: 0.0,
        }
    }

    fn add_client_upload(&mut self, name: &str, size_bytes: usize) {
        let size_kb = size_bytes as f64 / 1024.0;
        self.client_upload.insert(name.to_string(), size_kb);
        self.total += size_kb;
    }

    fn add_server_to_server(&mut self, name: &str, size_bytes: usize) {
        let size_kb = size_bytes as f64 / 1024.0;
        self.server_to_server.insert(name.to_string(), size_kb);
        self.total += size_kb;
    }

    fn add_collection(&mut self, name: &str, size_bytes: usize) {
        let size_kb = size_bytes as f64 / 1024.0;
        self.collection.insert(name.to_string(), size_kb);
        self.total += size_kb;
    }

    fn print_breakdown(&self) {
        println!("=== Network Message Sizes (KB) ===");
        println!("Total: {:.3} KB", self.total);
        
        println!("\n--- Client Upload ---");
        for (name, size_kb) in &self.client_upload {
            println!("  {}: {:.3} KB", name, size_kb);
        }
        
        println!("\n--- Server-to-Server (Ping-pong Protocol) ---");
        for (name, size_kb) in &self.server_to_server {
            println!("  {}: {:.3} KB", name, size_kb);
        }
        
        println!("\n--- Collection ---");
        for (name, size_kb) in &self.collection {
            println!("  {}: {:.3} KB", name, size_kb);
        }
    }
}

fn measure_message_sizes(input_length: usize, bitwidth: usize) -> NetworkMessages {
    let mut messages = NetworkMessages::new();
    
    // Setup metadata
    let task_id = TaskId::from([1u8; 32]);
    let report_id = ReportId::from([2u8; 16]);
    let report_metadata = ReportMetadata::new(
        report_id,
        Time::from_seconds_since_epoch(1_000_000_000),
        vec![], // No public extensions
    );

    // Create VDAF instance
    let chunk_length = optimal_chunk_length(input_length * bitwidth);
    let vdaf = Prio3SumVec::new_sum_vec(2, bitwidth, input_length, chunk_length).unwrap();
    let verify_key = [3u8; 32];
    let aggregation_param = ();

    // Create measurement
    let measurement = (0..input_length)
        .map(|_| 1u128 >> (128 - bitwidth))
        .collect::<Vec<_>>();

    // Generate VDAF transcript
    let transcript = run_vdaf(
        &vdaf,
        &task_id,
        &verify_key,
        &aggregation_param,
        &report_id,
        &measurement,
    );

    // Measure client upload messages (what actually gets sent over the network)
    let leader_input_share_size = transcript.leader_input_share.get_encoded().unwrap().len();
    messages.add_client_upload("leader_input_share", leader_input_share_size);
    
    // Helper input share (encrypted) 
    let helper_input_share_size = transcript.helper_input_share.get_encoded().unwrap().len();
    messages.add_client_upload("helper_input_share", helper_input_share_size);
    
    // Public share (plaintext)
    let public_share_size = transcript.public_share.get_encoded().unwrap().len();
    messages.add_client_upload("public_share", public_share_size);

    // Measure server-to-server ping-pong messages
    for (i, transition) in transcript.leader_prepare_transitions.iter().enumerate() {
        if let Some(message) = transition.message() {
            let message_size = message.get_encoded().unwrap().len();
            messages.add_server_to_server(&format!("leader_message_{}", i), message_size);
        }
    }
    
    for (i, transition) in transcript.helper_prepare_transitions.iter().enumerate() {
        if let Some(message) = transition.message() {
            let message_size = message.get_encoded().unwrap().len();
            messages.add_server_to_server(&format!("helper_message_{}", i), message_size);
        }
    }

    // Measure collection messages (encrypted output shares)
    let leader_output_share_size = transcript.leader_output_share.get_encoded().unwrap().len();
    messages.add_collection("leader_output_share", leader_output_share_size);
    
    let helper_output_share_size = transcript.helper_output_share.get_encoded().unwrap().len();
    messages.add_collection("helper_output_share", helper_output_share_size);

    messages
}

fn main() {
    println!("Prio3SumVec Message Size Analysis");
    println!("================================\n");

    //let input_lengths = vec![1, 8, 16, 64, 128];
    //let bitwidths = vec![1, 8];
    let input_lengths = vec![1];
    let bitwidths = vec![1];

    for (length, bitwidth) in iproduct!(&input_lengths, &bitwidths) {
        let messages = measure_message_sizes(*length, *bitwidth);
        messages.print_breakdown();
        println!("\n");
    }
} 