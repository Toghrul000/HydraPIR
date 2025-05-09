use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use cuckoo_lib::{
    calculate_required_table_size, CuckooHashTable, CuckooError,
};
use dpf_half_tree_lib::{self, calculate_pir_config};

use crate::ms_kpir::{
    Query, Answer, CsvRow, ServerSync, SyncResponse, ByteArrayEntry, ConfigData,
    UpdateSingleEntryRequest,
    pir_service_server::PirService,
    pir_service_client::PirServiceClient,
};


// --- Server Configuration ---
const STORAGE_MB: u64 = 256;
const TOTAL_STORAGE_BYTES: u64 = STORAGE_MB * 1024 * 1024;
const DESIRED_ENTRY_SIZE_BYTES: usize = 256;
const ENTRY_U64_COUNT: usize = DESIRED_ENTRY_SIZE_BYTES / 8;
const MAX_REHASH_ATTEMPTS_PER_CONFIG: usize = 1;

#[derive(Debug)]
pub struct MyPIRService {
    cuckoo_table: Arc<Mutex<CuckooHashTable<ENTRY_U64_COUNT>>>,
    num_buckets: Arc<Mutex<usize>>,
    bucket_size: Arc<Mutex<usize>>,
    bucket_bits: Arc<Mutex<u32>>,
}

impl Default for MyPIRService {
    fn default() -> Self {
        let (table_size, n_bits) = calculate_required_table_size(
            TOTAL_STORAGE_BYTES,
            DESIRED_ENTRY_SIZE_BYTES,
        );
        println!(
            "Calculated Table Size: {} slots (2^{}) ({} bytes total capacity)",
            table_size,
            n_bits,
            table_size * DESIRED_ENTRY_SIZE_BYTES
        );

        let cuckoo_table = CuckooHashTable::<ENTRY_U64_COUNT>::new(table_size)
            .expect("Failed to create CuckooHashTable");

        let (calculated_db_size, calculated_num_buckets, calculated_bucket_size, calculated_bucket_bits) = 
            calculate_pir_config(n_bits as usize);

        println!("--- Configuration Calculation ---");
        println!("For N = {}", n_bits);
        println!("Calculated DB_SIZE:     {}", calculated_db_size);
        println!("Calculated NUM_BUCKETS: {}", calculated_num_buckets);
        println!("Calculated BUCKET_SIZE: {}", calculated_bucket_size);
        println!("Calculated BUCKET_BITS: {}", calculated_bucket_bits);
        println!("---------------------------------");

        Self {
            cuckoo_table: Arc::new(Mutex::new(cuckoo_table)),
            num_buckets: Arc::new(Mutex::new(calculated_num_buckets)),
            bucket_size: Arc::new(Mutex::new(calculated_bucket_size)),
            bucket_bits: Arc::new(Mutex::new(calculated_bucket_bits)),
        }
    }
}

#[tonic::async_trait]
impl PirService for MyPIRService {
    async fn pir_query(
        &self,
        request: Request<Query>,
    ) -> Result<Response<Answer>, Status> {
        let query = request.into_inner();
        println!("Received query with dpf_key: {:?}", query.dpf_key);
        
        // TODO: Process the DPF key and perform the PIR query on the server's database.
        // For now, simply return a dummy answer.
        let data = b"dummy answer".to_vec();
        let answer = Answer { data };

        Ok(Response::new(answer))
    }

    async fn stream_csv_data(
        &self,
        request: Request<tonic::Streaming<CsvRow>>,
    ) -> Result<Response<SyncResponse>, Status> {
        let mut stream = request.into_inner();
        let mut successful_insertions = 0;
        let mut failed_insertions_count = 0;
        let mut line_count = 0;
        let mut keys_failed_insertion: Vec<(String, String)> = Vec::new();

        let mut cuckoo_table = self.cuckoo_table.lock().await;

        while let Some(csv_row) = stream.message().await? {
            line_count += 1;
            let key = csv_row.key;
            let value = csv_row.value;

            match cuckoo_table.insert_tracked(key.clone(), value.clone(), None) {
                Ok(_) => {
                    successful_insertions += 1;
                }
                Err(e @ CuckooError::InsertionFailed(_)) => {
                    if failed_insertions_count < 10 {
                        eprintln!(
                            "Insertion failed for key '{}' (line {}): {}",
                            key,
                            line_count,
                            e
                        );
                    } else if failed_insertions_count == 10 {
                        eprintln!("(Further insertion errors suppressed)");
                    }
                    failed_insertions_count += 1;
                    keys_failed_insertion.push((key, value));
                }
                Err(e) => {
                    return Err(Status::internal(format!(
                        "Unexpected Cuckoo error during insertion for key '{}': {}",
                        key, e
                    )));
                }
            }

            if line_count % 50000 == 0 {
                println!(
                    "  Processed {} CSV records ({} successful, {} failed)... Load: {:.2}%",
                    line_count,
                    successful_insertions,
                    failed_insertions_count,
                    cuckoo_table.load_factor() * 100.0
                );
            }
        }

        // Attempt Rehash Loop WITH FAILED items
        let mut final_failed_count = failed_insertions_count;

        if !keys_failed_insertion.is_empty() {
            println!(
                "\n--- Attempting Rehash Loop WITH FAILED items ({}) ---",
                keys_failed_insertion.len()
            );

            match cuckoo_table.rehash_loop_with_failed(
                keys_failed_insertion,
                MAX_REHASH_ATTEMPTS_PER_CONFIG
            ) {
                Ok(_) => {
                    println!("Rehash loop WITH FAILED items completed successfully.");
                    final_failed_count = 0;
                }
                Err((e, still_failed_items)) => {
                    eprintln!("Rehash loop WITH FAILED items failed definitively: {}", e);
                    println!("Table state restored to before the last failed attempt within the loop.");
                    final_failed_count = still_failed_items.len();
                    if !still_failed_items.is_empty() {
                        eprintln!("{} items could not be inserted even after rehash loop:", final_failed_count);
                        for (key, _) in still_failed_items.iter().take(5) {
                            eprintln!("  - {}", key);
                        }
                        if final_failed_count > 5 {
                            eprintln!("  ...");
                        }
                    }
                }
            }
            println!(
                "Final Load Factor after rehash loop attempt: {:.2}%",
                cuckoo_table.load_factor() * 100.0
            );
            println!("Remaining failed insertions after loop: {}", final_failed_count);
        }

        println!("TEST db[1] = {:?}", cuckoo_table.table[1]);

        Ok(Response::new(SyncResponse {
            success: true,
            message: format!(
                "Processed {} records ({} successful, {} failed)",
                line_count,
                successful_insertions,
                final_failed_count
            ),
        }))
    }


    async fn send_server_addresses(
        &self,
        request: Request<ServerSync>,
    ) -> Result<Response<SyncResponse>, Status> {
        let server_sync = request.into_inner();
        let server_addresses = server_sync.server_addresses;

        // Create a client for each server and send the CuckooHashTable details
        for server_addr in server_addresses {
            let mut client = PirServiceClient::connect(format!("http://{}", server_addr))
                .await
                .map_err(|e| Status::internal(format!("Failed to connect to server {}: {}", server_addr, e)))?;

            // Clone the table data we need before creating the stream
            let table_data = {
                let cuckoo_table = self.cuckoo_table.lock().await;
                let table: Vec<_> = cuckoo_table.table.iter().map(|arr| arr.to_vec()).collect();
                let hash_keys: Vec<Vec<u8>> = cuckoo_table.hash_keys.iter().map(|key| key.to_vec()).collect();
                let table_size = cuckoo_table.table_size;
                let mask = cuckoo_table.mask;
                let num_hashes = cuckoo_table.num_hashes;
                (table, hash_keys, table_size, mask, num_hashes)
            };

            let outbound_stream = async_stream::stream! {
                for (i, byte_array) in table_data.0.iter().enumerate() {
                    let chunk = ByteArrayEntry {
                        index: i as u32,
                        value: byte_array.clone(),
                    };
                    yield chunk;
                }
                println!("Client: Finished preparing all chunks to send.");
            };

            // Send table details to server
            let response = client.stream_byte_arrays(Request::new(outbound_stream)).await
                .map_err(|e| Status::internal(format!("Failed to sync with server {}: {}", server_addr, e)))?;

            let response_inner = response.into_inner();
            if response_inner.success {
                let config_data_proto = ConfigData {
                    table_size: table_data.2 as u64,
                    mask: table_data.3 as u64,
                    num_hashes: table_data.4 as u64,
                    hash_keys: table_data.1,
                };

                let response = client.send_configuration(Request::new(config_data_proto)).await?;
                println!("Server acknowledgement: {:?}", response.into_inner());
            }
        }

        Ok(Response::new(SyncResponse {
            success: true,
            message: "Successfully synchronized with all servers".to_string(),
        }))
    }


    async fn send_configuration(
        &self,
        request: Request<ConfigData>,
    ) -> Result<Response<SyncResponse>, Status> {
        let config_data_proto = request.into_inner();
        println!("Server: Received configuration data.");

        let mut cuckoo_table = self.cuckoo_table.lock().await;
        cuckoo_table.table_size = config_data_proto.table_size as usize;
        cuckoo_table.mask = config_data_proto.mask as usize;
        cuckoo_table.num_hashes = config_data_proto.num_hashes as usize;
        cuckoo_table.hash_keys = config_data_proto.hash_keys
            .into_iter()
            .map(|v| v.try_into().expect("Hash key must be 16 bytes"))
            .collect();

        println!("TEST db[1] = {:?}", cuckoo_table.table[1]);

        Ok(Response::new(SyncResponse {
            success: true,
            message: "Configuration sent successfully".to_string(),
        }))
    }




    async fn stream_byte_arrays(
        &self,
        request: Request<tonic::Streaming<ByteArrayEntry>>,
    ) -> Result<Response<SyncResponse>, Status> {
        let mut stream = request.into_inner();
        let mut line_count = 0;

        let mut cuckoo_table = self.cuckoo_table.lock().await;

        while let Some(byte_array_entry) = stream.message().await? {
            line_count += 1;
            let index = byte_array_entry.index;
            let value = byte_array_entry.value;
            cuckoo_table.table[index as usize] = value.try_into().expect("Failed to convert value");
        }

        Ok(Response::new(SyncResponse {
            success: true,
            message: format!(
                "Processed {} records while sending db",
                line_count,
            ),
        }))

    }

    async fn update_single_entry(
        &self,
        request: Request<UpdateSingleEntryRequest>,
    ) -> Result<Response<SyncResponse>, Status> {
        let update_request = request.into_inner();
        
        // Unwrap the CsvRow since it's an Option in the generated Rust code
        let csv_row = match update_request.csv_row {
            Some(row) => row,
            None => return Err(Status::invalid_argument("Missing CSV row data")),
        };
        
        let seed: [u8; 16] = update_request.deterministic_eviction_seed.try_into().unwrap();
        
        let key = csv_row.key;
        let value = csv_row.value;
        
        println!("Received update request for key: {}", key);
        
        let mut cuckoo_table = self.cuckoo_table.lock().await;
        
        match cuckoo_table.insert_tracked(key.clone(), value, Some(&seed)) {
            Ok(_) => {
                println!("Successfully inserted key '{}'", key);

                Ok(Response::new(SyncResponse {
                    success: true,
                    message: format!("Successfully inserted key '{}'", key),
                }))
            },
            Err(e) => {
                eprintln!("Failed to insert key '{}': {}", key, e);
                Err(Status::internal(format!("Failed to insert key '{}': {}", key, e)))
            }
        }
    }

}
