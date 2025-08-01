use clap::Parser;
use janus_core::{
    test_util::run_vdaf,
};
use janus_messages::{
    ReportId, TaskId,
};
use itertools::iproduct;
use janus_messages::codec::Encode;
use prio::vdaf::prio3::{Prio3SumVec, optimal_chunk_length};
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "message_sizes")]
#[command(about = "Analyze message sizes for Prio3SumVec VDAF")]
struct Args {
    /// Output results in CSV format
    #[arg(short, long)]
    csv: bool,
}

#[derive(Debug)]
struct NetworkMessages {
    client_upload: HashMap<String, f64>,      // Per-client costs (linear in number of clients)
    server_to_server: HashMap<String, f64>,   // Per-client costs (linear in number of clients)
    collection: HashMap<String, f64>,         // Per-batch costs (constant regardless of number of clients)
    total_per_client: f64,                    // Total per-client cost
    total_per_batch: f64,                     // Total per-batch cost
}

impl NetworkMessages {
    fn new() -> Self {
        Self {
            client_upload: HashMap::new(),
            server_to_server: HashMap::new(),
            collection: HashMap::new(),
            total_per_client: 0.0,
            total_per_batch: 0.0,
        }
    }

    fn add_client_upload(&mut self, name: &str, size_bytes: usize) {
        let size_kb = size_bytes as f64 / 1024.0;
        self.client_upload.insert(name.to_string(), size_kb);
        self.total_per_client += size_kb;
    }

    fn add_server_to_server(&mut self, name: &str, size_bytes: usize) {
        let size_kb = size_bytes as f64 / 1024.0;
        self.server_to_server.insert(name.to_string(), size_kb);
        self.total_per_client += size_kb;
    }

    fn add_collection(&mut self, name: &str, size_bytes: usize) {
        let size_kb = size_bytes as f64 / 1024.0;
        self.collection.insert(name.to_string(), size_kb);
        self.total_per_batch += size_kb;
    }

    fn print_breakdown(&self, input_length: usize, bitwidth: usize) {
        println!("=== Network Message Sizes (KB) ===");
        println!("Configuration: input_length={}, bitwidth={}\n", input_length, bitwidth);
        
        // Calculate totals
        let client_upload_total: f64 = self.client_upload.values().sum();
        let server_to_server_total: f64 = self.server_to_server.values().sum();
        let collection_total: f64 = self.collection.values().sum();
        
        println!("Client upload total (per-client): {:.3} KB", client_upload_total);
        println!("Server-to-server total (per-client): {:.3} KB", server_to_server_total);
        println!("Collection total (per-batch): {:.3} KB", collection_total);
        
        println!("\n--- Client Upload (Per-client costs) ---");
        for (name, size_kb) in &self.client_upload {
            println!("  {}: {:.3} KB", name, size_kb);
        }
        
        println!("\n--- Server-to-Server (Per-client costs) ---");
        for (name, size_kb) in &self.server_to_server {
            println!("  {}: {:.3} KB", name, size_kb);
        }
        
        println!("\n--- Collection (Per-batch costs) ---");
        for (name, size_kb) in &self.collection {
            println!("  {}: {:.3} KB", name, size_kb);
        }
    }

    fn to_csv_row(&self, input_length: usize, bitwidth: usize) -> String {
        let client_upload_total: f64 = self.client_upload.values().sum();
        let server_to_server_total: f64 = self.server_to_server.values().sum();
        let collection_total: f64 = self.collection.values().sum();
        
        format!("{},{},{:.3},{:.3},{:.3}", 
            bitwidth, 
            input_length, 
            client_upload_total, 
            server_to_server_total, 
            collection_total
        )
    }
}

fn measure_message_sizes(input_length: usize, bitwidth: usize) -> NetworkMessages {
    let mut messages = NetworkMessages::new();
    
    // Setup metadata
    let task_id = TaskId::from([1u8; 32]);
    let report_id = ReportId::from([2u8; 16]);
    
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
    let args = Args::parse();
    
    if !args.csv {
        println!("Prio3SumVec Message Size Analysis");
        println!("================================\n");
    } else {
        // CSV header
        println!("bitwidth,length,client_upload_total,server_to_server_total,collection_total");
    }

    //let input_lengths = vec![1, 8, 16, 64, 128];
    //let bitwidths = vec![1, 8];
    let bitwidths = vec![1];
    //let bitwidths = vec![1, 10, 20, 30, 40, 50, 60];
    let input_lengths = vec![1, 10, 20, 30, 40, 50, 60];

    // Create all combinations and sort by bitwidth, then length
    let mut combinations: Vec<_> = iproduct!(&input_lengths, &bitwidths)
        .map(|(length, bitwidth)| (*length, *bitwidth))
        .collect();
    combinations.sort_by(|(length1, bitwidth1), (length2, bitwidth2)| {
        bitwidth1.cmp(bitwidth2).then(length1.cmp(length2))
    });

    for (length, bitwidth) in combinations {
        let messages = measure_message_sizes(length, bitwidth);
        
        if args.csv {
            println!("{}", messages.to_csv_row(length, bitwidth));
        } else {
            messages.print_breakdown(length, bitwidth);
            println!("\n");
        }
    }
} 
