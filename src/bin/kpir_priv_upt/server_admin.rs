use std::error::Error;
use tonic::Request;
use async_stream::stream;
use crate::ms_kpir::{
    pir_service_private_update_client::PirServicePrivateUpdateClient,
    CsvRow,
    ServerSync,
};

pub async fn run_admin_client(
    csv_file_path: &str,
    server_addresses: &[String],
) -> Result<(), Box<dyn Error>> {
    println!("\n--- Performing Insertions from {} ---", csv_file_path);

    if !std::path::Path::new(csv_file_path).exists() {
        return Err(Box::<dyn Error>::from(format!(
            "CSV file not found at '{}'",
            csv_file_path
        )));
    }

    let first_server_addr = &server_addresses[0];
    let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", first_server_addr)).await?;
    println!("Connected to server at {}", first_server_addr);

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

    // Send the stream to server
    let response = client.stream_csv_data(Request::new(outbound)).await?;
    let response = response.into_inner();
    println!("Client: Server acknowledgement: {:?}", response);

    // If CSV streaming was successful and there are other servers to sync with
    if response.success && server_addresses.len() > 1 {
        let server_sync = ServerSync {
            server_addresses: server_addresses[1..].to_vec(),
        };
        
        let sync_response = client.send_server_addresses(Request::new(server_sync)).await?;
        let sync_response = sync_response.into_inner();
        println!("Client: Server addresses sync response: {:?}", sync_response);
    }

    Ok(())
}


