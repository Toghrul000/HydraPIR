use std::error::Error;
use rand::Rng;
use tonic::Request;
use async_stream::stream;
use crate::ms_kpir::{
    bit_optimized_pir_service_client::BitOptimizedPirServiceClient,
    CsvRow,
    ServerSync,
    UpdateSingleEntryRequest, SoftDeleteRequest, InsertSingleEntryRequest
};

pub async fn run_admin_client(
    csv_file_path: &str,
    server_addresses: &[String],
) -> Result<(), Box<dyn Error>> {
    println!("\n--- Performing Insertions from {} ---", csv_file_path);

    // Check if file exists
    if !std::path::Path::new(csv_file_path).exists() {
        return Err(Box::<dyn Error>::from(format!(
            "CSV file not found at '{}'",
            csv_file_path
        )));
    }

    // Connect to first server
    let first_server_addr = &server_addresses[0];
    let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", first_server_addr)).await?;
    println!("Connected to server at {}", first_server_addr);

    // Open and read CSV file
    let file = std::fs::File::open(csv_file_path)?;
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_reader(file);

    let outbound = stream! {
        let mut line_count = 0;

        for result in rdr.records() {
            line_count += 1;
            let record = match result {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Client: Error reading CSV record at line {}: {}", line_count, e);
                    break;
                }
            };

            let key_opt = record.get(0);
            let value_opt = record.get(1);

            match (key_opt, value_opt) {
                (Some(k_str), Some(v_str)) => {
                    let key = k_str.trim().to_string();
                    let value = v_str.to_string();

                    if key.is_empty() {
                        println!("Client: Warning: Skipping line {} due to empty key.", line_count);
                        continue;
                    }

                    // println!("Client: Sending record from line {}: Key='{}', Value='{}'", line_count, key, value);
                    let csv_row_proto = CsvRow {
                        key,
                        value,
                    };
                    yield csv_row_proto;
                }
                (None, _) => {
                    eprintln!("Client: Error: Missing key column in CSV at line {}. Record: {:?}", line_count, record);
                    break;
                }
                (_, None) => {
                    eprintln!("Client: Error: Missing value column in CSV at line {}. Record: {:?}", line_count, record);
                    break;
                }
            }
        }
        println!("Client: Finished processing CSV file for streaming.");
    };

    // Send the stream to server and wait for response
    let response = client.stream_csv_data(Request::new(outbound)).await?;
    let response = response.into_inner();
    println!("Client: Server acknowledgement: {:?}", response);

    // If CSV streaming was successful and there are other servers to sync with
    if response.success && server_addresses.len() > 1 {
        println!("Sending second server address for sync");
        let server_sync = ServerSync {
            server_addresses: server_addresses[1..].to_vec(),
        };
        
        let sync_response = client.send_server_addresses(Request::new(server_sync)).await?;
        let sync_response = sync_response.into_inner();
        println!("Client: Server addresses sync response: {:?}", sync_response);
    }

    Ok(())
}

pub async fn update_servers(
    key: String,
    value: String,
    server_addresses: &[String],
    upsert: bool,
) -> Result<(), Box<dyn Error>> {
    println!("\n--- Updating servers with key: {} ---", key);

    // First check if we have any server addresses
    if server_addresses.is_empty() {
        return Err(Box::<dyn Error>::from("No server addresses provided"));
    }

    // Connect to first server
    let seed: [u8; 16] = rand::rng().random();
    for server_addr in server_addresses{
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await?;
        println!("Connected to server at {}", server_addr);
    
        // Create the CsvRow for the single key-value pair
        let csv_row = CsvRow {
            key: key.clone(),
            value: value.clone(),
        };
        
        // Create the UpdateSingleEntryRequest
        let update_request = UpdateSingleEntryRequest {
            csv_row: Some(csv_row),
            deterministic_eviction_seed: seed.to_vec(),
            upsert: upsert,
        };
    
        // Send the update request to the first server
        println!("Sending update request to server at {}", server_addr);
        let response = client.update_single_entry(Request::new(update_request)).await?;
        let response = response.into_inner();
        
        println!("Server response: {}", response.message);

    }

    
    Ok(())
}

pub async fn insert_servers(
    key: String,
    value: String,
    server_addresses: &[String],
) -> Result<(), Box<dyn Error>> {
    println!("\n--- Updating servers with key: {} ---", key);

    // First check if we have any server addresses
    if server_addresses.is_empty() {
        return Err(Box::<dyn Error>::from("No server addresses provided"));
    }

    // Connect to first server
    let seed: [u8; 16] = rand::rng().random();
    for server_addr in server_addresses{
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await?;
        println!("Connected to server at {}", server_addr);
    
        // Create the CsvRow for the single key-value pair
        let csv_row = CsvRow {
            key: key.clone(),
            value: value.clone(),
        };
        
        // Create the UpdateSingleEntryRequest
        let update_request = InsertSingleEntryRequest {
            csv_row: Some(csv_row),
            deterministic_eviction_seed: seed.to_vec(),
        };
    
        // Send the update request to the first server
        println!("Sending update request to server at {}", server_addr);
        let response = client.insert_single_entry(Request::new(update_request)).await?;
        let response = response.into_inner();
        
        println!("Server response: {}", response.message);

    }

    
    Ok(())
}


pub async fn soft_delete_entry(
    key: String,
    server_addresses: &[String],
) -> Result<(), Box<dyn Error>> {
    println!("\n--- Removing key: {} from servers ---", key);

    // First check if we have any server addresses
    if server_addresses.is_empty() {
        return Err(Box::<dyn Error>::from("No server addresses provided"));
    }

    for server_addr in server_addresses{
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await?;
        println!("Connected to server at {}", server_addr);
    
        // Create the CsvRow for the single key-value pair
        let soft_delete_request = SoftDeleteRequest {
            key: key.clone()
        };
        
    
        // Send the update request to the first server
        println!("Sending update request to server at {}", server_addr);
        let response = client.soft_delete_entry(Request::new(soft_delete_request)).await?;
        let response = response.into_inner();
        
        println!("Server response: {}", response.message);

    }
    
    Ok(())
}
