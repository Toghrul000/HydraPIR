use std::sync::Arc;
use dpf_half_tree_bit_lib::{dmpf_bit_pir_query_eval_additive, dpf_priv_xor_update_additive_buckets, BitDPFKey, DPFKeyArray};
use dpf_half_tree_lib::calculate_pir_config;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::sync::{mpsc, Mutex};
use tonic::{Request, Response, Status};
use cuckoo_lib::{
    calculate_required_table_size, CuckooError, CuckooHashTableBucketedAdditiveShare
};

use std::collections::HashMap;
use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};

use crate::ms_kpir::PrivUpdateRequest;
use crate::ms_kpir::{
    CsvRow, ServerSync, SyncResponse, ByteShareArrayEntry, ConfigData,
    ClientSessionInitRequest, ClientSessionInitResponse,
    BucketBitOptimizedKeys, ServerResponse, BucketEvalResult, ClientCleanupRequest,
    bit_optimized_pir_service_private_update_server::BitOptimizedPirServicePrivateUpdate,
    bit_optimized_pir_service_private_update_client::BitOptimizedPirServicePrivateUpdateClient,
};

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

#[derive(Debug)]
pub struct MyPIRService {
    cuckoo_table: Arc<Mutex<CuckooHashTableBucketedAdditiveShare<ENTRY_U64_COUNT>>>,
    num_buckets: Arc<Mutex<usize>>,
    bucket_size: Arc<Mutex<usize>>,
    bucket_bits: Arc<Mutex<u32>>,
    n_bits: Arc<Mutex<u32>>,
    client_sessions: Arc<Mutex<HashMap<String, ClientSession>>>,
}

fn spawn_share_streaming_task(
    server_addr_str: String,
    mut rx_channel: mpsc::Receiver<ByteShareArrayEntry>,
    config_data_proto: ConfigData,
    target_server_name: String,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        println!(
            "Task for {}: Connecting to {}",
            target_server_name, server_addr_str
        );

        let mut grpc_client = match BitOptimizedPirServicePrivateUpdateClient::connect(format!("http://{}", server_addr_str)).await {
            Ok(c) => c,
            Err(e) => {
                let err_msg = format!(
                    "Task for {}: Failed to connect to server {}: {}",
                    target_server_name, server_addr_str, e
                );
                eprintln!("{}", err_msg);
                return Err(err_msg);
            }
        };

        let stream_target_name = target_server_name.clone(); // Clone for use in the stream
        let outbound_share_stream = async_stream::stream! {
            while let Some(share_entry) = rx_channel.recv().await {
                yield share_entry;
            }
            println!("Task for {}: Stream finished producing shares.", stream_target_name);
        };

        println!("Task for {}: Sending share stream...", target_server_name);
        match grpc_client
            .stream_byte_share_arrays(Request::new(outbound_share_stream))
            .await
        {
            Ok(response) => {
                let response_inner = response.into_inner();
                if !response_inner.success {
                    let err_msg = format!(
                        "Task for {}: Server {} (share stream) indicated failure: {}",
                        target_server_name, server_addr_str, response_inner.message
                    );
                    eprintln!("{}", err_msg);
                    return Err(err_msg);
                }
                println!(
                    "Task for {}: Share stream acknowledged by server {}.",
                    target_server_name, server_addr_str
                );
            }
            Err(e) => {
                let err_msg = format!(
                    "Task for {}: Failed to stream shares to server {}: {}",
                    target_server_name, server_addr_str, e
                );
                eprintln!("{}", err_msg);
                return Err(err_msg);
            }
        }

        println!(
            "Task for {}: Sending configuration to {}...",
            target_server_name, server_addr_str
        );
        match grpc_client.send_configuration(Request::new(config_data_proto)).await {
            Ok(response) => {
                println!(
                    "Task for {}: Config acknowledged by server {}: {:?}",
                    target_server_name, server_addr_str, response.into_inner()
                );
            }
            Err(e) => {
                let err_msg = format!(
                    "Task for {}: Failed to send configuration to server {}: {}",
                    target_server_name, server_addr_str, e
                );
                eprintln!("{}", err_msg);
                return Err(err_msg);
            }
        }

        Ok(())
    })
}


pub type EntryI64<const N: usize> = [i64; N];

// Creates two XOR additive shares from an i64 array.
fn create_i64_xor_additive_shares<const N: usize>(
    original_values: &EntryI64<N>,
    rng: &mut impl RngCore,
) -> (EntryI64<N>, EntryI64<N>) {
    let mut share1 = [0i64; N];
    let mut share2 = [0i64; N];
    for i in 0..N {
        share1[i] = rng.next_u64() as i64;
        share2[i] = original_values[i] ^ share1[i]; 
    }
    (share1, share2)
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

        let cuckoo_table = CuckooHashTableBucketedAdditiveShare::<ENTRY_U64_COUNT>::new(calculated_num_buckets, calculated_bucket_size)
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
impl BitOptimizedPirServicePrivateUpdate for MyPIRService {
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

        let results = dmpf_bit_pir_query_eval_additive::<ENTRY_U64_COUNT>(
            server_id,
            &dpf_keys,
            &cuckoo_table.table,  
            num_buckets,
            bucket_size,
            &hash_key,
            &aes,
        );

        let bucket_results = results.into_iter().map(|result| {
            BucketEvalResult {
                value: result.to_vec(),
            }
        }).collect();

        let answer = ServerResponse {
            bucket_result: bucket_results,
        };
        
        Ok(Response::new(answer))
    }



    async fn private_update(
        &self,
        request: Request<PrivUpdateRequest>,
    ) -> Result<Response<SyncResponse>, Status> {
        let query = request.into_inner();
        let client_id = query.client_id;
        let server_id = query.server_id as usize;
        let update_keys = query.update_keys;
        
        // Get hash key and AES key from client sessions - keep lock alive
        let sessions = self.client_sessions.lock().await;
        let session = sessions.get(&client_id).ok_or_else(|| {
            Status::not_found(format!("Client session not found: {}", client_id))
        })?;
        
        let hs_key: [u8; 16] = session.hs_key.as_slice().try_into().map_err(|_| {
            Status::internal("Invalid hash key size")
        })?;
        
        let aes_key: [u8; 16] = session.aes_key.as_slice().try_into().map_err(|_| {
            Status::internal("Invalid AES key size")
        })?;
        let aes = create_aes(&aes_key);

        let update_dpf_keys: Vec<DPFKeyArray<ENTRY_U64_COUNT>> = update_keys.iter().map(|update_key| {
            let mut cw_levels = Vec::new();
            for cw in &update_key.cw_levels {
                let level: [u8; 16] = cw.as_slice().try_into().map_err(|_| {
                    Status::internal("Invalid correction word size")
                }).unwrap();
                cw_levels.push(level);
            }
            
            let cw_n_proto = update_key.cw_n.as_ref().ok_or_else(|| {
                Status::internal("Missing CW_n in DPFKey")
            }).unwrap();
            
            let hcw: [u8; 15] = cw_n_proto.hcw.as_slice().try_into().map_err(|_| {
                Status::internal("Invalid HCW size")
            }).unwrap();
            
            let seed: [u8; 16] = update_key.seed.as_slice().try_into().map_err(|_| {
                Status::internal("Invalid seed size")
            }).unwrap();
            
            let cw_n = (hcw, cw_n_proto.lcw0 as u8, cw_n_proto.lcw1 as u8);
            
            DPFKeyArray {
                n: update_key.n as usize,
                seed,
                cw_levels,
                cw_n,
                cw_np1: update_key.cw_np1.as_slice().try_into().unwrap(),
            }
        }).collect();

        // Get mutable access to the table and evaluate the DPF key directly
        let mut cuckoo_table = self.cuckoo_table.lock().await;
        let bucket_size = self.bucket_size.lock().await;
        dpf_priv_xor_update_additive_buckets::<ENTRY_U64_COUNT>(
            server_id as u8,
            &update_dpf_keys,
            &mut cuckoo_table.table,
            &bucket_size,
            &hs_key,
            &aes,
        );

        Ok(Response::new(SyncResponse {
            success: true,
            message: format!("Successfully updated entry for server {}", server_id),
        }))
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
        let other_server_addresses = server_sync.server_addresses; // Expects S2, S3, S4 addrs

        println!(
            "S1: Received Sync Server addresses: {:?}",
            other_server_addresses
        );

        if other_server_addresses.len() != 3 {
            return Err(Status::invalid_argument(
                "Expected 3 other server addresses for a 4-server setup.",
            ));
        }

        let s2_addr = &other_server_addresses[0];
        let s3_addr = &other_server_addresses[1];
        let s4_addr = &other_server_addresses[2];

        // --- Extract common configuration data (once) ---
        let (
            local_hash_keys_vec,
            table_size_usize,
            mask_usize,
            k_choices_usize,
            num_total_buckets_usize,
            slots_per_bucket_usize,
            bucket_selection_key_vec,
            original_table_len,
        ) = {
            let cuckoo_table_guard = self.cuckoo_table.lock().await;
            (
                cuckoo_table_guard
                    .local_hash_keys
                    .iter()
                    .map(|key| key.to_vec())
                    .collect::<Vec<Vec<u8>>>(),
                cuckoo_table_guard.table_size,
                cuckoo_table_guard.mask,
                cuckoo_table_guard.k_choices,
                cuckoo_table_guard.num_total_buckets,
                cuckoo_table_guard.slots_per_bucket,
                cuckoo_table_guard.bucket_selection_key.to_vec(),
                cuckoo_table_guard.table.len(),
            )
        };

        let config_data_proto_template = ConfigData {
            table_size: table_size_usize as u64,
            mask: mask_usize as u64,
            k_choices: k_choices_usize as u64,
            local_hash_keys: local_hash_keys_vec.clone(),
            bucket_selection_key: bucket_selection_key_vec.clone(),
            num_total_buckets: num_total_buckets_usize as u64,
            slots_per_bucket: slots_per_bucket_usize as u64,
        };

        // --- Create channels for each target server's shares ---
        const CHANNEL_BUFFER_SIZE: usize = 1000;
        let (s2_tx, s2_rx) = mpsc::channel::<ByteShareArrayEntry>(CHANNEL_BUFFER_SIZE);
        let (s3_tx, s3_rx) = mpsc::channel::<ByteShareArrayEntry>(CHANNEL_BUFFER_SIZE);
        let (s4_tx, s4_rx) = mpsc::channel::<ByteShareArrayEntry>(CHANNEL_BUFFER_SIZE);

        // --- Spawn tasks to stream shares to each server ---
        let s2_handle = spawn_share_streaming_task(
            s2_addr.clone(),
            s2_rx,
            config_data_proto_template.clone(),
            "S2".to_string(),
        );
        let s3_handle = spawn_share_streaming_task(
            s3_addr.clone(),
            s3_rx,
            config_data_proto_template.clone(),
            "S3".to_string(),
        );
        let s4_handle = spawn_share_streaming_task(
            s4_addr.clone(),
            s4_rx,
            config_data_proto_template.clone(),
            "S4".to_string(),
        );

        // --- Iterate through the local table, generate shares, and send to channels ---
        let table_arc = Arc::clone(&self.cuckoo_table);
        // Process in batches to manage lock duration and provide backpressure via channels
        const BATCH_SIZE_PROCESSING: usize = 1000;
        let mut i = 0;
        let mut rng = StdRng::from_os_rng(); // Create RNG for share generation

        println!(
            "S1: Starting to process and distribute shares for {} entries.",
            original_table_len
        );

        while i < original_table_len {
            let end = std::cmp::min(i + BATCH_SIZE_PROCESSING, original_table_len);

            let mut s2_batch_shares = Vec::with_capacity(end - i);
            let mut s3_batch_shares = Vec::with_capacity(end - i);
            let mut s4_batch_shares = Vec::with_capacity(end - i);

            { // Lock scope for reading original data and modifying S1's local table
                let mut table_lock = table_arc.lock().await;
                for idx in i..end {
                    let original_entry_as_i64 = table_lock.table[idx].clone();

                    // Shares for S1 (local) and S2
                    let (s1_share_a, s2_share_a) =
                        create_i64_xor_additive_shares::<ENTRY_U64_COUNT>(
                            &original_entry_as_i64,
                            &mut rng,
                        );

                    // Shares for S3 and S4 (from the same original entry)
                    let (s3_share_b, s4_share_b) =
                        create_i64_xor_additive_shares::<ENTRY_U64_COUNT>(
                            &original_entry_as_i64,
                            &mut rng,
                        );

                    // Update S1's local table to hold its share for Pair A
                    table_lock.table[idx] = s1_share_a;

                    // Prepare shares for sending via channels
                    s2_batch_shares.push(ByteShareArrayEntry {
                        index: idx as u32,
                        value: s2_share_a.to_vec(),
                    });
                    s3_batch_shares.push(ByteShareArrayEntry {
                        index: idx as u32,
                        value: s3_share_b.to_vec(), // S3 gets share1_B
                    });
                    s4_batch_shares.push(ByteShareArrayEntry {
                        index: idx as u32,
                        value: s4_share_b.to_vec(), // S4 gets share2_B
                    });
                }
            } // S1's table_lock released

            // Asynchronously send batched shares to respective channels
            // Handle potential channel send errors (e.g., if a receiver task panicked)
            for share in s2_batch_shares {
                if s2_tx.send(share).await.is_err() {
                    eprintln!("S1: S2 channel closed prematurely. Aborting S2 send.");
                    break; 
                }
            }
            for share in s3_batch_shares {
                if s3_tx.send(share).await.is_err() {
                    eprintln!("S1: S3 channel closed prematurely. Aborting S3 send.");
                    break;
                }
            }
            for share in s4_batch_shares {
                if s4_tx.send(share).await.is_err() {
                    eprintln!("S1: S4 channel closed prematurely. Aborting S4 send.");
                    break;
                }
            }

            i = end;
            if i % (BATCH_SIZE_PROCESSING * 10) == 0 { 
                println!(
                    "S1: Processed and queued shares for {} / {} entries.",
                    i, original_table_len
                );
            }
        }
        println!("S1: Finished processing and queuing all shares.");

        // Close the senders to signal the end of streams to the consumer tasks
        drop(s2_tx);
        drop(s3_tx);
        drop(s4_tx);

        // Wait for all streaming tasks to complete and collect their results
        let results = tokio::try_join!(s2_handle, s3_handle, s4_handle);
        
        match results {
            Ok((res_s2, res_s3, res_s4)) => {
                println!("S1: S2 sync task result: {:?}", res_s2);
                println!("S1: S3 sync task result: {:?}", res_s3);
                println!("S1: S4 sync task result: {:?}", res_s4);
                if res_s2.is_err() || res_s3.is_err() || res_s4.is_err() {
                    // Construct a more detailed error message if needed
                    let errors = vec![res_s2.err(), res_s3.err(), res_s4.err()].into_iter().flatten().collect::<Vec<_>>();
                    return Err(Status::internal(format!(
                        "One or more server sync operations failed: {:?}", errors
                    )));
                }
            }
            Err(join_err) => {
                return Err(Status::internal(format!(
                    "Error joining server sync tasks: {}",
                    join_err
                )));
            }
        }

        Ok(Response::new(SyncResponse {
            success: true,
            message: "Successfully initiated synchronization with all servers".to_string(),
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


    async fn stream_byte_share_arrays(
        &self,
        request: Request<tonic::Streaming<ByteShareArrayEntry>>,
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
        
        let num_buckets = *self.num_buckets.lock().await as u32;
        let bucket_size = *self.bucket_size.lock().await as u32;
        let bucket_bits = *self.bucket_bits.lock().await;
        let n_bits = *self.n_bits.lock().await;
        
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
}
