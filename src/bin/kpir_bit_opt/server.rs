use std::sync::Arc;
use dpf_half_tree_lib::calculate_pir_config;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use cuckoo_lib::{
    calculate_required_table_size, CuckooError, CuckooHashTableBucketed
};

use std::collections::HashMap;
use dpf_half_tree_bit_lib::{dmpf_bit_pir_query_eval, BitDPFKey};
use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};

use crate::ms_kpir::{
    CsvRow, ServerSync, SyncResponse, ByteArrayEntry, ConfigData,
    UpdateSingleEntryRequest, ClientSessionInitRequest, ClientSessionInitResponse,
    bit_optimized_pir_service_server::BitOptimizedPirService,
    bit_optimized_pir_service_client::BitOptimizedPirServiceClient,
    BucketBitOptimizedKeys, ServerResponse, BucketEvalResult, ClientCleanupRequest, CuckooKeys
};

// Import constants from config module
use kpir::config::{
    TOTAL_STORAGE_BYTES,
    DESIRED_ENTRY_SIZE_BYTES,
    ENTRY_U64_COUNT,
    MAX_REHASH_ATTEMPTS_PER_CONFIG,
    BUCKET_NUM_OPTION,
};

// const STORAGE_MB: u64 = 256;
// const TOTAL_STORAGE_BYTES: u64 = STORAGE_MB * 1024 * 1024;
// const DESIRED_ENTRY_SIZE_BYTES: usize = 256;
// const ENTRY_U64_COUNT: usize = DESIRED_ENTRY_SIZE_BYTES / 8;
// const MAX_REHASH_ATTEMPTS_PER_CONFIG: usize = 1;

// Client session data
#[derive(Debug, Clone)]
struct ClientSession {
    aes_key: Vec<u8>,
    hs_key: Vec<u8>,
}

// Helper function to create aes instance
fn create_aes(key: &[u8; 16]) -> Aes128 {
    let aes_key = GenericArray::clone_from_slice(key);
    Aes128::new(&aes_key)
}

#[derive(Debug)]
pub struct MyPIRService {
    cuckoo_table: Arc<Mutex<CuckooHashTableBucketed<{ ENTRY_U64_COUNT }>>>,
    num_buckets: Arc<Mutex<usize>>,
    bucket_size: Arc<Mutex<usize>>,
    bucket_bits: Arc<Mutex<u32>>,
    n_bits: Arc<Mutex<u32>>,
    client_sessions: Arc<Mutex<HashMap<String, ClientSession>>>,
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

        let (calculated_db_size, calculated_num_buckets, calculated_bucket_size, calculated_bucket_bits) = 
            calculate_pir_config(n_bits as usize, BUCKET_NUM_OPTION);

        println!("--- Configuration Calculation ---");
        println!("For N = {}", n_bits);
        println!("Calculated DB_SIZE:     {}", calculated_db_size);
        println!("Calculated NUM_BUCKETS: {}", calculated_num_buckets);
        println!("Calculated BUCKET_SIZE: {}", calculated_bucket_size);
        println!("Calculated BUCKET_BITS: {}", calculated_bucket_bits);
        println!("---------------------------------");

        let cuckoo_table = CuckooHashTableBucketed::<{ ENTRY_U64_COUNT }>::new(calculated_num_buckets, calculated_bucket_size)
        .expect("Failed to create CuckooHashTable");

        Self {
            cuckoo_table: Arc::new(Mutex::new(cuckoo_table)),
            num_buckets: Arc::new(Mutex::new(calculated_num_buckets)),
            bucket_size: Arc::new(Mutex::new(calculated_bucket_size)),
            bucket_bits: Arc::new(Mutex::new(calculated_bucket_bits)),
            n_bits: Arc::new(Mutex::new(n_bits)),
            client_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl BitOptimizedPirService for MyPIRService {
    async fn pir_query(
        &self,
        request: Request<BucketBitOptimizedKeys>,
    ) -> Result<Response<ServerResponse>, Status> {
        let query = request.into_inner();
        let client_id = query.client_id;
        let server_id = query.server_id as usize;
        let bucket_keys = query.bucket_key;
        
        // Get hash key and AES key from client sessions - keep lock alive
        let sessions = self.client_sessions.lock().await;
        let session = sessions.get(&client_id).ok_or_else(|| {
            Status::not_found(format!("Client session not found: {}", client_id))
        })?;
        
        let hash_key: [u8; 16] = session.hs_key.as_slice().try_into().map_err(|_| {
            Status::internal("Invalid hash key size")
        })?;
        
        let aes_key: [u8; 16] = session.aes_key.as_slice().try_into().map_err(|_| {
            Status::internal("Invalid AES key size")
        })?;
        let aes = create_aes(&aes_key);
        
        // Get table and configuration - keep locks alive for the duration of query evaluation
        let cuckoo_table = self.cuckoo_table.lock().await;
        let num_buckets = *self.num_buckets.lock().await;
        let bucket_size = *self.bucket_size.lock().await;
        
        // Convert protobuf DPFKey to Rust DPFKey
        let dpf_keys = bucket_keys.into_iter().map(|proto_key| {
            let mut cw_levels = Vec::new();
            for cw in proto_key.cw_levels {
                let level: [u8; 16] = cw.try_into().map_err(|_| {
                    Status::internal("Invalid correction word size")
                })?;
                cw_levels.push(level);
            }
            
            let cw_n_proto = proto_key.cw_n.ok_or_else(|| {
                Status::internal("Missing CW_n in DPFKey")
            })?;
            
            let hcw: [u8; 15] = cw_n_proto.hcw.try_into().map_err(|_| {
                Status::internal("Invalid HCW size")
            })?;
            
            let seed: [u8; 16] = proto_key.seed.try_into().map_err(|_| {
                Status::internal("Invalid seed size")
            })?;
            
            let cw_n = (hcw, cw_n_proto.lcw0 as u8, cw_n_proto.lcw1 as u8);
            
            Ok::<_, Status>(BitDPFKey {
                n: proto_key.n as usize,
                seed,
                cw_levels,
                cw_n,
                cw_np1: proto_key.cw_np1.try_into().unwrap(),
            })
        }).collect::<Result<Vec<_>, _>>()?;

        // Evaluate the query - using references to table and other data
        let results = dmpf_bit_pir_query_eval::<{ ENTRY_U64_COUNT }>(
            server_id,
            &dpf_keys,
            &cuckoo_table.table,
            num_buckets,
            bucket_size,
            &hash_key,
            &aes,
        );
        
        // Convert to protobuf response format
        let bucket_results = results.into_iter().map(|result| {
            BucketEvalResult {
                value: result.to_vec(),
            }
        }).collect();
        
        // Return the server response
        let answer = ServerResponse {
            bucket_result: bucket_results,
        };
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

        // println!("TEST db[1] = {:?}", cuckoo_table.table[1]);

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
        println!("Received Sync Server address");

        // Create a client for each server and send the CuckooHashTable details
        for server_addr in server_addresses {
            let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr))
                .await
                .map_err(|e| Status::internal(format!("Failed to connect to server {}: {}", server_addr, e)))?;

            // Extract configuration data without cloning the entire table
            let config_data = {
                let cuckoo_table = self.cuckoo_table.lock().await;
                let local_hash_keys: Vec<Vec<u8>> = cuckoo_table.local_hash_keys.iter().map(|key| key.to_vec()).collect();
                let table_size = cuckoo_table.table_size;
                let mask = cuckoo_table.mask;
                let k_choices = cuckoo_table.k_choices;
                let num_total_buckets = cuckoo_table.num_total_buckets;
                let slots_per_bucket = cuckoo_table.slots_per_bucket;
                let bucket_selection_key = cuckoo_table.bucket_selection_key.to_vec();
                let table_len = cuckoo_table.table.len();
                
                (local_hash_keys, table_size, mask, k_choices, num_total_buckets, slots_per_bucket, bucket_selection_key, table_len)
            };
            
            // Clone the Arc to share with the stream
            let table_arc = Arc::clone(&self.cuckoo_table);
            
            // Create a stream that processes entries in batches to avoid holding the lock too long
            let outbound_stream = async_stream::stream! {
                const BATCH_SIZE: usize = 10000; // Process this many entries at once
                let table_len = config_data.7;
                let mut i = 0;
                
                while i < table_len {
                    let end = std::cmp::min(i + BATCH_SIZE, table_len);
                    let mut batch = Vec::with_capacity(end - i);
                    
                    // Only lock for the duration of copying this batch
                    {
                        let table_lock = table_arc.lock().await;
                        for idx in i..end {
                            batch.push(ByteArrayEntry {
                                index: idx as u32,
                                value: table_lock.table[idx].to_vec(),
                            });
                        }
                    } // Lock is released here
                    
                    // Yield each entry in the batch without holding the lock
                    for entry in batch {
                        yield entry;
                    }
                    
                    i = end;
                    
                    if i % 50000 == 0 {
                        println!("Client: Prepared {} of {} chunks to send...", i, table_len);
                    }
                }
                
                println!("Client: Finished preparing all chunks to send.");
            };

            // Send table details to server
            println!("Sending table data to sync server");
            let response = client.stream_byte_arrays(Request::new(outbound_stream)).await
                .map_err(|e| Status::internal(format!("Failed to sync with server {}: {}", server_addr, e)))?;

            let response_inner = response.into_inner();
            if response_inner.success {
                let config_data_proto = ConfigData {
                    table_size: config_data.1 as u64,
                    mask: config_data.2 as u64,
                    k_choices: config_data.3 as u64,
                    local_hash_keys: config_data.0,
                    bucket_selection_key: config_data.6,
                    num_total_buckets: config_data.4 as u64,
                    slots_per_bucket: config_data.5 as u64,
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
        cuckoo_table.k_choices = config_data_proto.k_choices as usize;
        cuckoo_table.local_hash_keys = config_data_proto.local_hash_keys
            .into_iter()
            .map(|v| v.try_into().expect("Hash key must be 16 bytes"))
            .collect();
        cuckoo_table.bucket_selection_key = config_data_proto.bucket_selection_key.try_into().unwrap();
        cuckoo_table.num_total_buckets = config_data_proto.num_total_buckets as usize;
        cuckoo_table.slots_per_bucket = config_data_proto.slots_per_bucket as usize;

        // println!("TEST db[1] = {:?}", cuckoo_table.table[1]);

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
        println!("Received Stream from other server");

        let mut cuckoo_table = self.cuckoo_table.lock().await;

        while let Some(byte_array_entry) = stream.message().await? {
            line_count += 1;
            let index = byte_array_entry.index;
            let value = byte_array_entry.value;
            cuckoo_table.table[index as usize] = value.try_into().expect("Failed to convert value");
            if line_count % 50000 == 0 {
                println!(
                    "  Processed {} CSV records",
                    line_count,
                );
            }
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
        
        match cuckoo_table.insert_tracked_update_checked(key.clone(), value, Some(&seed)) {
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

    async fn init_client_session(
        &self,
        request: Request<ClientSessionInitRequest>,
    ) -> Result<Response<ClientSessionInitResponse>, Status> {
        let init_request = request.into_inner();
        let client_id = init_request.client_id;
        let aes_key = init_request.aes_key;
        let hs_key = init_request.hs_key;
        
        // Store client session info
        let session = ClientSession {
            aes_key,
            hs_key,
        };
        
        {
            let mut sessions = self.client_sessions.lock().await;
            sessions.insert(client_id.clone(), session);
            println!("Initialized session for client: {}", client_id);
        }
        
        // Return PIR configuration parameters
        let num_buckets = *self.num_buckets.lock().await as u32;
        let bucket_size = *self.bucket_size.lock().await as u32;
        let bucket_bits = *self.bucket_bits.lock().await;
        let n_bits = *self.n_bits.lock().await;
        
        // Get hash keys from Cuckoo table
        let hash_keys = {
            let cuckoo_table = self.cuckoo_table.lock().await;

            (cuckoo_table.bucket_selection_key.to_vec(), cuckoo_table.local_hash_keys.iter().map(|key| key.to_vec()).collect())
        };
        
        Ok(Response::new(ClientSessionInitResponse {
            num_buckets,
            bucket_size,
            bucket_bits,
            n_bits,
            local_hash_keys: hash_keys.1,
            bucket_selection_key: hash_keys.0,
            entry_u64_count: ENTRY_U64_COUNT as u64,
        }))
    }

    async fn cleanup_client_session(
        &self,
        request: Request<ClientCleanupRequest>,
    ) -> Result<Response<SyncResponse>, Status> {
        let cleanup_request = request.into_inner();
        let client_id = cleanup_request.client_id;
        
        let mut sessions = self.client_sessions.lock().await;
        match sessions.remove(&client_id) {
            Some(_) => {
                println!("Successfully removed client session: {}", client_id);
                Ok(Response::new(SyncResponse {
                    success: true,
                    message: format!("Successfully removed client session: {}", client_id),
                }))
            },
            None => {
                println!("Client session not found: {}", client_id);
                Ok(Response::new(SyncResponse {
                    success: false,
                    message: format!("Client session not found: {}", client_id),
                }))
            }
        }
    }

    async fn send_cuckoo_keys(
        &self,
        request: Request<CuckooKeys>,
    ) -> Result<Response<SyncResponse>, Status> {
        let cuckoo_keys = request.into_inner();
        println!("Received Cuckoo keys from client");

        let mut cuckoo_table = self.cuckoo_table.lock().await;
        
        // Convert the received keys to the expected format
        cuckoo_table.local_hash_keys = cuckoo_keys.local_hash_keys
            .into_iter()
            .map(|v| v.try_into().expect("Hash key must be 16 bytes"))
            .collect();
        cuckoo_table.bucket_selection_key = cuckoo_keys.bucket_selection_key.try_into().unwrap();

        println!("Successfully updated Cuckoo table keys");
        println!("Number of local hash keys: {}", cuckoo_table.local_hash_keys.len());

        Ok(Response::new(SyncResponse {
            success: true,
            message: "Successfully updated Cuckoo table keys".to_string(),
        }))
    }
}
