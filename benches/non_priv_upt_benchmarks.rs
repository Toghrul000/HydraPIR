use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
use tokio::runtime::Runtime;
use kpir::ms_kpir::bit_optimized_pir_service_client::BitOptimizedPirServiceClient;
use kpir::ms_kpir::{ClientSessionInitRequest, ClientCleanupRequest, CsvRow, UpdateSingleEntryRequest, SoftDeleteRequest, InsertSingleEntryRequest};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use rand::Rng;
use uuid::Uuid;
use std::error::Error;
use tonic::Request;

// Default server addresses for benchmarks
const DEFAULT_SERVERS: [&str; 2] = ["127.0.0.1:50051", "127.0.0.1:50052"];

// Copy the admin functions directly into the benchmark file
pub async fn update_servers(
    key: String,
    value: String,
    server_addresses: &[String],
    upsert: bool,
) -> Result<(), Box<dyn Error>> {
    // First check if we have any server addresses
    if server_addresses.is_empty() {
        return Err(Box::<dyn Error>::from("No server addresses provided"));
    }

    // Connect to first server
    let seed: [u8; 16] = rand::rng().random();
    for server_addr in server_addresses{
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await?;
    
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
    
        let response = client.update_single_entry(Request::new(update_request)).await?;
        let _response = response.into_inner();

    }

    
    Ok(())
}

pub async fn insert_servers(
    key: String,
    value: String,
    server_addresses: &[String],
) -> Result<(), Box<dyn Error>> {

    // First check if we have any server addresses
    if server_addresses.is_empty() {
        return Err(Box::<dyn Error>::from("No server addresses provided"));
    }

    // Connect to first server
    let seed: [u8; 16] = rand::rng().random();
    for server_addr in server_addresses{
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await?;
    
        // Create the CsvRow for the single key-value pair
        let csv_row = CsvRow {
            key: key.clone(),
            value: value.clone(),
        };
        
        // Create the InsertSingleEntryRequest
        let insert_request = InsertSingleEntryRequest {
            csv_row: Some(csv_row),
            deterministic_eviction_seed: seed.to_vec(),
        };
    
        let response = client.insert_single_entry(Request::new(insert_request)).await?;
        let _response = response.into_inner();

    }

    
    Ok(())
}

pub async fn soft_delete_entry(
    key: String,
    server_addresses: &[String],
) -> Result<(), Box<dyn Error>> {

    // First check if we have any server addresses
    if server_addresses.is_empty() {
        return Err(Box::<dyn Error>::from("No server addresses provided"));
    }

    for server_addr in server_addresses{
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await?;
    
        // Create the soft delete request
        let soft_delete_request = SoftDeleteRequest {
            key: key.clone()
        };

        let response = client.soft_delete_entry(Request::new(soft_delete_request)).await?;
        let _response = response.into_inner();
    }
    
    Ok(())
}

#[derive(Clone)]
pub struct ClientSession {
    pub client_id: String,
    pub aes_key: [u8; 16],
    pub hash_key: [u8; 16],
    pub num_buckets: u32,
    pub bucket_size: u32,
    pub bucket_bits: u32,
    pub bucket_selection_key: [u8; 16],
    pub local_hash_keys: Vec<[u8; 16]>,
    pub entry_u64_count: usize,
}

// Initialize a new client session with the servers
pub async fn initialize_session(server_addrs: &[&str]) -> Result<ClientSession, Box<dyn std::error::Error>> {
    // Generate a unique client ID
    let client_id = Uuid::new_v4().to_string();
    
    let mut rng = StdRng::from_os_rng();
    // Generate random AES key and hash key
    let mut aes_key_bytes = [0u8; 16];
    rng.fill_bytes(&mut aes_key_bytes);
    
    let mut hash_key = [0u8; 16];
    rng.fill_bytes(&mut hash_key);
    
    // Create a session with default values that will be updated
    let mut session = ClientSession {
        client_id: client_id.clone(),
        aes_key: aes_key_bytes,
        hash_key,
        num_buckets: 0,
        bucket_size: 0,
        bucket_bits: 0,
        bucket_selection_key: [0u8; 16],
        local_hash_keys: Vec::new(),
        entry_u64_count: 0,
    };
    
    // Send session init request to each server
    let mut first_server_keys: Option<(Vec<Vec<u8>>, Vec<u8>)> = None;
    
    for (i, &addr) in server_addrs.iter().enumerate() {
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", addr)).await?;
        
        let init_request = ClientSessionInitRequest {
            client_id: client_id.clone(),
            aes_key: aes_key_bytes.to_vec(),
            hs_key: hash_key.to_vec(),
        };
        
        let response = client.init_client_session(tonic::Request::new(init_request)).await?;
        let response_inner = response.into_inner();
        
        // Only store the configuration parameters once (they should be the same from all servers)
        if session.num_buckets == 0 {
            session.num_buckets = response_inner.num_buckets;
            session.bucket_size = response_inner.bucket_size;
            session.bucket_bits = response_inner.bucket_bits;
            session.local_hash_keys = response_inner.local_hash_keys.iter()
                .map(|k| {
                    let slice: &[u8] = k.as_slice();
                    let array: [u8; 16] = slice.try_into().expect("Expected a 16-byte key");
                    array
                })
                .collect();
            // Store the first server's keys to send to other servers
            first_server_keys = Some((
                response_inner.local_hash_keys.clone(),
                response_inner.bucket_selection_key.clone()
            ));
            // Now use the cloned value for the session
            session.bucket_selection_key = response_inner.bucket_selection_key.try_into().unwrap();
            session.entry_u64_count = response_inner.entry_u64_count as usize;
        } else if i > 0 {
            // For subsequent servers, check if their keys are different from first server's keys
            if let Some((first_local_hash_keys, first_bucket_selection_key)) = &first_server_keys {
                // Check if either the local hash keys or bucket selection key is different
                let keys_are_different = 
                    // Check if lengths are different
                    response_inner.local_hash_keys.len() != first_local_hash_keys.len() ||
                    // Check if bucket selection key is different
                    response_inner.bucket_selection_key != *first_bucket_selection_key ||
                    // Check if any local hash key is different
                    response_inner.local_hash_keys.iter()
                        .zip(first_local_hash_keys.iter())
                        .any(|(a, b)| a != b);

                if keys_are_different {
                    println!("Server at {} has different keys than first server, updating...", addr);
                    let cuckoo_keys = kpir::ms_kpir::CuckooKeys {
                        local_hash_keys: first_local_hash_keys.clone(),
                        bucket_selection_key: first_bucket_selection_key.clone(),
                    };
                    
                    let response = client.send_cuckoo_keys(tonic::Request::new(cuckoo_keys)).await?;
                    let response_inner = response.into_inner();
                    if !response_inner.success {
                        println!("Warning: Failed to sync Cuckoo keys with server at {}", addr);
                    } else {
                        println!("Successfully synced Cuckoo keys with server at {}", addr);
                    }
                } else {
                    println!("Server at {} already has the same keys as first server, skipping update", addr);
                }
            }
        }
        
        println!("Initialized session with server at {}", addr);
    }
    
    println!("Client session initialized with ID: {}", client_id);
    println!("PIR parameters: num_buckets={}, bucket_size={}, bucket_bits={}, k_choices={}", 
             session.num_buckets, session.bucket_size, session.bucket_bits, session.local_hash_keys.len());
    
    Ok(session)
}

pub async fn cleanup_client_session(session: &ClientSession, server_addrs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Cleaning up client session...");
    
    for &addr in server_addrs {
        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", addr)).await?;
        
        let cleanup_request = ClientCleanupRequest {
            client_id: session.client_id.clone(),
        };
        
        match client.cleanup_client_session(tonic::Request::new(cleanup_request)).await {
            Ok(response) => {
                let response_inner = response.into_inner();
                if response_inner.success {
                    println!("Successfully cleaned up session on server {}", addr);
                } else {
                    eprintln!("Failed to cleanup session on server {}: {}", addr, response_inner.message);
                }
            },
            Err(e) => eprintln!("Error cleaning up session on server {}: {}", addr, e),
        }
    }
    
    println!("Client session cleanup completed");
    Ok(())
}

async fn setup_benchmark_session() -> ClientSession {
    // Initialize a session with the running servers
    initialize_session(&DEFAULT_SERVERS).await.expect("Failed to initialize session")
}

// Helper function to generate random keys within the valid range
fn generate_random_keys(num_keys: usize, num_buckets: u32, bucket_size: u32) -> Vec<String> {
    let mut rng = StdRng::from_os_rng();
    let total_entries = num_buckets as usize * bucket_size as usize;
    let mut keys = Vec::with_capacity(num_keys);
    
    for _ in 0..num_keys {
        let random_index = rng.random_range(0..total_entries);
        keys.push(format!("key{}", random_index));
    }
    keys
}

// Helper function to generate random values for updates
fn generate_random_value() -> String {
    let mut rng = StdRng::from_os_rng();
    let length = rng.random_range(10..50);
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();
    (0..length).map(|_| chars[rng.random_range(0..chars.len())]).collect()
}

// Helper function to generate random new keys for insertion
fn generate_random_new_keys(num_keys: usize) -> Vec<(String, String)> {
    let mut rng = StdRng::from_os_rng();
    let mut key_value_pairs = Vec::with_capacity(num_keys);
    
    for i in 0..num_keys {
        let key = format!("new_key_{}_{}", i, rng.random::<u32>());
        let value = generate_random_value();
        key_value_pairs.push((key, value));
    }
    key_value_pairs
}

fn bench_update_servers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("Update Servers (upsert=false)");
    group.measurement_time(Duration::from_secs(10));
    
    // Generate 3 random keys for testing
    let test_keys = generate_random_keys(3, session.num_buckets, session.bucket_size);
    
    // Test each server individually
    for (server_idx, &server_addr) in DEFAULT_SERVERS.iter().enumerate() {
        let server_addresses = vec![server_addr.to_string()];
        
        for key in test_keys.iter() {
            let new_value = generate_random_value();
            let bench_id = format!("server_{}_update", server_idx);
            group.bench_with_input(BenchmarkId::new(bench_id, key), key, |b, query_key| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(update_servers(
                            query_key.clone(),
                            new_value.clone(),
                            &server_addresses,
                            false // upsert = false
                        ).await)
                    })
                });
            });
        }
    }
    group.finish();
}

fn bench_soft_delete_entry(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("Soft Delete Entry");
    group.measurement_time(Duration::from_secs(10));
    
    // Generate 3 random keys for testing
    let test_keys = generate_random_keys(3, session.num_buckets, session.bucket_size);
    
    // Test each server individually
    for (server_idx, &server_addr) in DEFAULT_SERVERS.iter().enumerate() {
        let server_addresses = vec![server_addr.to_string()];
        
        for key in test_keys.iter() {
            let bench_id = format!("server_{}_soft_delete", server_idx);
            group.bench_with_input(BenchmarkId::new(bench_id, key), key, |b, query_key| {
                b.iter(|| {
                    rt.block_on(async {
                        black_box(soft_delete_entry(
                            query_key.clone(),
                            &server_addresses
                        ).await)
                    })
                });
            });
        }
    }
    group.finish();
}

fn bench_insert_servers(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    // Calculate 5% of database size
    let total_db_size = session.num_buckets as usize * session.bucket_size as usize;
    let max_insertions = (total_db_size as f64 * 0.05) as usize;
    
    println!("Database size: {} entries", total_db_size);
    println!("Max insertions (5%): {} entries", max_insertions);
    
    let mut group = c.benchmark_group("Insert Servers");
    
    // Calculate appropriate measurement time based on max insertions
    // Assuming each insertion takes ~1ms, we want to limit total time
    let estimated_time_per_insertion = 1; // milliseconds
    let max_measurement_time = std::cmp::min(
        (max_insertions * estimated_time_per_insertion) / 10, // Divide by 10 for 10 samples
        500 // Cap at 500ms
    );
    
    group.measurement_time(Duration::from_millis(max_measurement_time as u64));
    group.sample_size(10);  // Minimum required by Criterion
    
    // Test each server individually
    for (server_idx, &server_addr) in DEFAULT_SERVERS.iter().enumerate() {
        let server_addresses = vec![server_addr.to_string()];
        
        let bench_id = format!("server_{}_insert", server_idx);
        group.bench_function(bench_id, |b| {
            b.iter_with_setup(
                || {
                    // Setup: Generate a unique key-value pair (not measured)
                    let mut rng = StdRng::from_os_rng();
                    let unique_id = rng.random::<u64>();
                    let key = format!("bench_key_{}", unique_id);
                    let value = generate_random_value();
                    (key, value)
                },
                |(key, value)| {
                    // This is what gets measured: only the actual insertion
                    rt.block_on(async {
                        let _ = black_box(insert_servers(
                            key,
                            value,
                            &server_addresses
                        ).await);
                    });
                }
            );
        });
    }
    group.finish();
}

// Configure the benchmark group with default settings
criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_update_servers,
             bench_soft_delete_entry,
             //bench_insert_servers
}
criterion_main!(benches);
