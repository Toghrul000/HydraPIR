use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
use tokio::runtime::Runtime;
use kpir::ms_kpir::bit_optimized_pir_service_client::BitOptimizedPirServiceClient;
use kpir::ms_kpir::{ClientSessionInitRequest, BucketBitOptimizedKeys, BitDpfKey, CuckooKeys, ClientCleanupRequest};
use kpir::ms_kpir::bit_dpf_key;
use cuckoo_lib::get_hierarchical_indices;
use dpf_half_tree_bit_lib::{dmpf_bit_pir_query_gen, dmpf_bit_pir_reconstruct_servers};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use uuid::Uuid;
use std::error::Error;
use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};
use kpir::config::ENTRY_U64_COUNT;
use rand::Rng;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::Path;

// Default server addresses for benchmarks
const DEFAULT_SERVERS: [&str; 2] = ["127.0.0.1:50051", "127.0.0.1:50052"];
//const DEFAULT_SERVERS: [&str; 1] = ["127.0.0.1:50051"]; 

#[derive(Clone)]
pub struct ClientSession {
    pub client_id: String,
    pub aes_key: [u8; 16],
    pub hash_key: [u8; 16],
    pub num_buckets: u32,
    pub bucket_size: u32,
    pub bucket_bits: u32,
    pub bucket_selection_key: [u8; 16], // Cuckoo bucket chosing key
    pub local_hash_keys: Vec<[u8; 16]>,  // Cuckoo hash keys from server
    pub entry_u64_count: usize,
}

// Initialize a new client session with the servers
pub async fn initialize_session(server_addrs: &[&str]) -> Result<ClientSession, Box<dyn std::error::Error>> {
    let client_id = Uuid::new_v4().to_string();
    let mut rng = StdRng::from_os_rng();
    let mut aes_key_bytes = [0u8; 16];
    rng.fill_bytes(&mut aes_key_bytes);
    
    let mut hash_key = [0u8; 16];
    rng.fill_bytes(&mut hash_key);

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
            first_server_keys = Some((
                response_inner.local_hash_keys.clone(),
                response_inner.bucket_selection_key.clone()
            ));
            session.bucket_selection_key = response_inner.bucket_selection_key.try_into().unwrap();
            session.entry_u64_count = response_inner.entry_u64_count as usize;
        } else if i > 0 {
            if let Some((first_local_hash_keys, first_bucket_selection_key)) = &first_server_keys {
                let keys_are_different = 
                    response_inner.local_hash_keys.len() != first_local_hash_keys.len() ||
                    response_inner.bucket_selection_key != *first_bucket_selection_key ||
                    response_inner.local_hash_keys.iter()
                        .zip(first_local_hash_keys.iter())
                        .any(|(a, b)| a != b);

                if keys_are_different {
                    println!("Server at {} has different keys than first server, updating...", addr);
                    let cuckoo_keys = CuckooKeys {
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

pub async fn execute_pir_query_and_display_results(
    session: &ClientSession,
    server_addrs: &[&str],
    input_query_key: &str,
) -> Result<Option<(usize, String, [u64; ENTRY_U64_COUNT])>, Box<dyn Error>> {

    let global_indexes = get_hierarchical_indices(
        &session.bucket_selection_key, 
        &session.local_hash_keys, 
        &session.local_hash_keys.len(), 
        &(session.num_buckets as usize), 
        &(session.bucket_size as usize), 
        input_query_key);

    let target_points: Vec<u32> = global_indexes.iter().map(|x| *x as u32).collect();
    
    // Get AES instance - needed for the DPF
    let aes = create_aes(&session.aes_key);

    let client_keys = dmpf_bit_pir_query_gen(&target_points, session.num_buckets as usize, session.bucket_size as usize, session.bucket_bits, &session.hash_key, &aes);
    
    let mut server_futures = Vec::new();

    for (i, &addr) in server_addrs.iter().enumerate() {
        let client_keys_for_server = &client_keys[i];
        let client_future = async move {

            let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", addr)).await?;
            

            let proto_bucket_keys = client_keys_for_server.clone().iter().map(|key| {

                let cwn = bit_dpf_key::Cwn {
                    hcw: key.cw_n.0.to_vec(),
                    lcw0: key.cw_n.1 as u32,
                    lcw1: key.cw_n.2 as u32,
                };
                

                BitDpfKey {
                    n: key.n as u32,
                    seed: key.seed.to_vec(),
                    cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                    cw_n: Some(cwn),
                    cw_np1: key.cw_np1.to_vec(),
                }
            }).collect();

            // Create BucketKeys request
            let request = tonic::Request::new(BucketBitOptimizedKeys {
                client_id: session.client_id.clone(),
                server_id: i as u32,
                bucket_key: proto_bucket_keys,
            });

            let response = client.pir_query(request).await?;
            Ok::<_, Box<dyn Error>>(response.into_inner())

        };
        server_futures.push(client_future);
    }

    // Sequentially wait
    let mut answers = Vec::new();
    for future in server_futures {
        let answer = future.await?;  // Propagate error if any
        answers.push(answer);
    }

    // Convert the received answers to the format expected by dmpf_bit_pir_reconstruct_servers
    // We need to convert from ServerResponse to Vec<Vec<[i64; N]>>
    let all_server_results: Vec<Vec<[i64; ENTRY_U64_COUNT]>> = answers.into_iter().map(|server_response| {
        server_response.bucket_result.into_iter().map(|bucket_result| {
            let mut array = [0i64; ENTRY_U64_COUNT];
            for (i, val) in bucket_result.value.into_iter().enumerate() {
                if i < ENTRY_U64_COUNT {
                    array[i] = val;
                }
            }
            array
        }).collect()
    }).collect();


    let final_slots = dmpf_bit_pir_reconstruct_servers::<ENTRY_U64_COUNT>(
        &all_server_results,
        session.num_buckets as usize,
    );

    // --- Display Final Results ---
    let mut query_result = None;
    
    // Calculate which bucket each global index belongs to
    let bucket_size = session.bucket_size as usize;
    let bucket_to_global_index = global_indexes.iter().map(|&global_idx| {
        let bucket_idx = global_idx / bucket_size;
        (bucket_idx, global_idx)
    }).collect::<Vec<_>>();
    
    for (bucket_idx, slot) in final_slots.iter().enumerate() {
        // Find the global index that corresponds to this bucket
        let global_index = bucket_to_global_index.iter()
            .find(|&&(bucket, _)| bucket == bucket_idx)
            .map(|&(_, global_idx)| global_idx);
            
        // Use the decode_entry from cuckoo_lib to decode the entry
        match cuckoo_lib::decode_entry(slot) {
            Ok(Some((key, value))) => {
                if key == input_query_key && global_index.is_some() {
                    query_result = Some((global_index.unwrap(), value, slot.clone()));
                }
            },
            Ok(None) => {
                //println!("  Bucket {}: Empty slot", bucket_idx);
            },
            Err(_e) => {
                //println!("  Bucket {}: Error decoding: {:?}", bucket_idx, e);
            }
        }
    }

    Ok(query_result)

}

// Helper function to create AES instance from key
pub fn create_aes(key: &[u8; 16]) -> Aes128 {
    let aes_key = GenericArray::clone_from_slice(key);
    Aes128::new(&aes_key)
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
    initialize_session(&DEFAULT_SERVERS).await.expect("Failed to initialize session")
}

// Helper function to generate random keys within the valid range
fn generate_random_keys(num_keys: usize, num_buckets: u32, bucket_size: u32) -> Vec<String> {
    let mut rng = StdRng::from_os_rng();
    let csv_path = Path::new("data/pgp_db_256_ecc.csv");
    
    // First, count the total number of lines in the CSV file
    let total_lines = if let Ok(file) = File::open(csv_path) {
        let reader = BufReader::new(file);
        reader.lines().count()
    } else {
        0
    };
    
    // If we couldn't read the file or it's empty, fall back to random generation
    if total_lines <= 1 { // 1 line would be just the header
        println!("Warning: Could not read CSV file or it's empty, falling back to random generation");
        let total_entries = num_buckets as usize * bucket_size as usize;
        let mut keys = Vec::with_capacity(num_keys);
        
        for _ in 0..num_keys {
            let random_index = rng.random_range(0..total_entries);
            keys.push(format!("key{}", random_index));
        }
        return keys;
    }
    
    // Generate random line numbers (skip line 0 which is the header)
    let mut random_line_numbers: Vec<usize> = (0..num_keys)
        .map(|_| rng.random_range(1..total_lines)) // Skip header line (line 0)
        .collect();
    
    // Read the specific random lines
    let mut keys = Vec::with_capacity(num_keys);
    if let Ok(file) = File::open(csv_path) {
        let reader = BufReader::new(file);
        for (line_num, line) in reader.lines().enumerate() {
            if let Ok(line) = line {
                if random_line_numbers.contains(&line_num) {
                    if let Some(key) = line.split(',').next() {
                        keys.push(key.to_string());
                    }
                    random_line_numbers.retain(|&x| x != line_num);
                    if keys.len() >= num_keys {
                        break;
                    }
                }
            }
        }
    }
    
    // If we didn't get enough keys, fill the rest with random generation
    while keys.len() < num_keys {
        let total_entries = num_buckets as usize * bucket_size as usize;
        let random_index = rng.random_range(0..total_entries);
        keys.push(format!("key{}", random_index));
    }
    
    keys
}

fn bench_dpf_key_generation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("DPF Key Generation");
    group.measurement_time(Duration::from_secs(10));
    
    // Generate 5 random keys for testing
    let test_keys = generate_random_keys(3, session.num_buckets, session.bucket_size);
    
    for key in test_keys.iter() {
        group.bench_with_input(BenchmarkId::new("key_gen", key), key, |b, query_key| {
            b.iter(|| {
                let global_indexes = cuckoo_lib::get_hierarchical_indices(
                    &session.bucket_selection_key,
                    &session.local_hash_keys,
                    &session.local_hash_keys.len(),
                    &(session.num_buckets as usize),
                    &(session.bucket_size as usize),
                    query_key
                );
                
                let target_points: Vec<u32> = global_indexes.iter().map(|x| *x as u32).collect();
                
                let aes = create_aes(&session.aes_key);
                black_box(dmpf_bit_pir_query_gen(
                    &target_points,
                    session.num_buckets as usize,
                    session.bucket_size as usize,
                    session.bucket_bits,
                    &session.hash_key,
                    &aes
                ))
            });
        });
    }
    group.finish();
}

fn bench_server_response_times(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("Server Response Times");
    group.measurement_time(Duration::from_secs(10));
    

    let test_keys = generate_random_keys(3, session.num_buckets, session.bucket_size);
    
    for key in test_keys.iter() {
        group.bench_with_input(BenchmarkId::new("server_response", key), key, |b, query_key| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(execute_pir_query_and_display_results(
                        &session,
                        &DEFAULT_SERVERS,
                        query_key
                    ).await)
                })
            });
        });
    }
    group.finish();
}

fn bench_individual_server_response_times(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("Individual Server Response Times");
    group.measurement_time(Duration::from_secs(10));
    

    let test_keys = generate_random_keys(3, session.num_buckets, session.bucket_size);
    
    for (server_idx, &server_addr) in DEFAULT_SERVERS.iter().enumerate() {
        for key in test_keys.iter() {
            let bench_id = format!("server_{}_response", server_idx);
            group.bench_with_input(BenchmarkId::new(bench_id, key), key, |b, query_key| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await.expect("Failed to connect to server");
                        

                        let global_indexes = get_hierarchical_indices(
                            &session.bucket_selection_key,
                            &session.local_hash_keys,
                            &session.local_hash_keys.len(),
                            &(session.num_buckets as usize),
                            &(session.bucket_size as usize),
                            query_key
                        );
                        
                        let target_points: Vec<u32> = global_indexes.iter().map(|x| *x as u32).collect();
                        
                        let aes = create_aes(&session.aes_key);
                        let client_keys = dmpf_bit_pir_query_gen(
                            &target_points,
                            session.num_buckets as usize,
                            session.bucket_size as usize,
                            session.bucket_bits,
                            &session.hash_key,
                            &aes
                        );
                        
                        let client_keys_for_server = &client_keys[server_idx];
                        let proto_bucket_keys = client_keys_for_server.iter().map(|key| {
                            let cwn = bit_dpf_key::Cwn {
                                hcw: key.cw_n.0.to_vec(),
                                lcw0: key.cw_n.1 as u32,
                                lcw1: key.cw_n.2 as u32,
                            };
                            
                            BitDpfKey {
                                n: key.n as u32,
                                seed: key.seed.to_vec(),
                                cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                                cw_n: Some(cwn),
                                cw_np1: key.cw_np1.to_vec(),
                            }
                        }).collect();

                        let request = tonic::Request::new(BucketBitOptimizedKeys {
                            client_id: session.client_id.clone(),
                            server_id: server_idx as u32,
                            bucket_key: proto_bucket_keys,
                        });

                        black_box(client.pir_query(request).await)
                    })
                });
            });
        }
    }
    group.finish();
}

fn bench_reconstruction(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("Reconstruction Time");
    group.measurement_time(Duration::from_secs(10));
    

    let test_keys = generate_random_keys(3, session.num_buckets, session.bucket_size);
    
    for key in test_keys.iter() {

        let all_server_results = rt.block_on(async {
            let mut results = Vec::new();
            for (server_idx, &server_addr) in DEFAULT_SERVERS.iter().enumerate() {
                let mut client = BitOptimizedPirServiceClient::connect(format!("http://{}", server_addr)).await.expect("Failed to connect");
                
                let global_indexes = get_hierarchical_indices(
                    &session.bucket_selection_key,
                    &session.local_hash_keys,
                    &session.local_hash_keys.len(),
                    &(session.num_buckets as usize),
                    &(session.bucket_size as usize),
                    key
                );
                
                let target_points: Vec<u32> = global_indexes.iter().map(|x| *x as u32).collect();
                
                let aes = create_aes(&session.aes_key);
                let client_keys = dmpf_bit_pir_query_gen(
                    &target_points,
                    session.num_buckets as usize,
                    session.bucket_size as usize,
                    session.bucket_bits,
                    &session.hash_key,
                    &aes
                );
                
                let client_keys_for_server = &client_keys[server_idx];
                let proto_bucket_keys = client_keys_for_server.iter().map(|key| {
                    let cwn = bit_dpf_key::Cwn {
                        hcw: key.cw_n.0.to_vec(),
                        lcw0: key.cw_n.1 as u32,
                        lcw1: key.cw_n.2 as u32,
                    };
                    
                    BitDpfKey {
                        n: key.n as u32,
                        seed: key.seed.to_vec(),
                        cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                        cw_n: Some(cwn),
                        cw_np1: key.cw_np1.to_vec(),
                    }
                }).collect();

                let request = tonic::Request::new(BucketBitOptimizedKeys {
                    client_id: session.client_id.clone(),
                    server_id: server_idx as u32,
                    bucket_key: proto_bucket_keys,
                });

                let response = client.pir_query(request).await.expect("Query failed");
                let server_response = response.into_inner();
                
                let bucket_results: Vec<[i64; ENTRY_U64_COUNT]> = server_response.bucket_result.into_iter()
                    .map(|bucket_result| {
                        let mut array = [0i64; ENTRY_U64_COUNT];
                        for (i, val) in bucket_result.value.into_iter().enumerate() {
                            if i < ENTRY_U64_COUNT {
                                array[i] = val as i64;
                            }
                        }
                        array
                    })
                    .collect();
                results.push(bucket_results);
            }
            results
        });


        group.bench_with_input(BenchmarkId::new("reconstruction", key), key, |b, _| {
            b.iter(|| {
                black_box(dmpf_bit_pir_reconstruct_servers::<ENTRY_U64_COUNT>(
                    &all_server_results,
                    session.num_buckets as usize,
                ));
            });
        });
    }
    group.finish();
}

// Configure the benchmark group with default settings
criterion_group! {
    name = benches;
    // Use Criterion's default configuration
    // - sample_size: 100 (number of samples to take)
    // - measurement_time: 5s (time to spend measuring each benchmark)
    // - plots: true (generate plots for results)
    // - warm_up_time: 3s (time to warm up before measuring)
    // - bootstrap_size: 100_000 (number of resamples for statistical analysis)
    config = Criterion::default();
    targets = bench_dpf_key_generation,
             // bench_server_response_times,
             bench_individual_server_response_times,
             bench_reconstruction
}
criterion_main!(benches); 