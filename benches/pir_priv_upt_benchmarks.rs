use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
use tokio::runtime::Runtime;
use kpir::ms_kpir::pir_service_private_update_client::PirServicePrivateUpdateClient;
use kpir::ms_kpir::{dpf_key, BucketKeys, ClientSessionInitRequest, DpfKey, DpfKeyBytes, PrivUpdateRequest};
use kpir::ms_kpir::dpf_key_bytes;
use cuckoo_lib::{get_hierarchical_indices, encode_entry, Entry};
use dpf_half_tree_lib::{dmpf_pir_query_gen, dmpf_pir_reconstruct_servers, dpf_gen_bytes};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use uuid::Uuid;
use std::error::Error;
use std::sync::Arc;
use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};
use kpir::config::ENTRY_U64_COUNT;

// Default server addresses for benchmarks (4 servers)
const DEFAULT_SERVERS: [&str; 4] = [
    "127.0.0.1:50051",
    "127.0.0.1:50052",
    "127.0.0.1:50053",
    "127.0.0.1:50054"
];

#[derive(Clone)]
pub struct ClientSession {
    pub client_id: String,
    pub aes_key: [u8; 16],
    pub hash_key: [u8; 16],
    pub num_buckets: u32,
    pub bucket_size: u32,
    pub bucket_bits: u32,
    pub n_bits: u32,
    pub bucket_selection_key: [u8; 16],
    pub local_hash_keys: Vec<[u8; 16]>,
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
        n_bits: 0,
        bucket_selection_key: [0u8; 16],
        local_hash_keys: Vec::new(),
        entry_u64_count: 0,
    };
    
    for &addr in server_addrs {
        let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await?;
        
        let init_request = ClientSessionInitRequest {
            client_id: client_id.clone(),
            aes_key: aes_key_bytes.to_vec(),
            hash_key: hash_key.to_vec(),
        };
        
        let response = client.init_client_session(tonic::Request::new(init_request)).await?;
        let response_inner = response.into_inner();
        
        if session.num_buckets == 0 {
            session.num_buckets = response_inner.num_buckets;
            session.bucket_size = response_inner.bucket_size;
            session.bucket_bits = response_inner.bucket_bits;
            session.n_bits = response_inner.n_bits;
            session.local_hash_keys = response_inner.local_hash_keys.iter()
                .map(|k| {
                    let slice: &[u8] = k.as_slice();
                    let array: [u8; 16] = slice.try_into().expect("Expected a 16-byte key");
                    array
                })
                .collect();
            session.bucket_selection_key = response_inner.bucket_selection_key.try_into().unwrap();
            session.entry_u64_count = response_inner.entry_u64_count as usize;
        }
        
        println!("Initialized session with server at {}", addr);
    }
    
    println!("Client session initialized with ID: {}", client_id);
    println!("PIR parameters: num_buckets={}, bucket_size={}, bucket_bits={}, k_choices={}", 
             session.num_buckets, session.bucket_size, session.bucket_bits, session.local_hash_keys.len());
    
    Ok(session)
}

// Helper function to create AES instance from key
fn create_aes(key: &[u8; 16]) -> Aes128 {
    let aes_key = GenericArray::clone_from_slice(key);
    Aes128::new(&aes_key)
}

async fn execute_pir_query(
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

    let beta = 1;
    let target_points: Vec<(u32, u32)> = global_indexes.iter().map(|x| (*x as u32, beta)).collect();
    
    let aes = create_aes(&session.aes_key);
    let client_keys = dmpf_pir_query_gen(&target_points, session.num_buckets as usize, session.bucket_size as usize, session.bucket_bits, &session.hash_key, &aes);
    
    let mut server_futures = Vec::new();

    for (group_index, addr_chunk) in server_addrs.chunks(2).enumerate() {
        for (_, &addr) in addr_chunk.iter().enumerate() {
            let client_keys_for_group = &client_keys[group_index];
            let client_future = async move {
                let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await?;
                
                let proto_bucket_keys = client_keys_for_group.clone().iter().map(|key| {
                    let cwn = dpf_key::Cwn {
                        hcw: key.cw_n.0.to_vec(),
                        lcw0: key.cw_n.1 as u32,
                        lcw1: key.cw_n.2 as u32,
                    };
        
                    DpfKey {
                        n: key.n as u32,
                        seed: key.seed.to_vec(),
                        cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                        cw_n: Some(cwn),
                        cw_np1: key.cw_np1,
                    }
                }).collect();
        
                let request = tonic::Request::new(BucketKeys {
                    client_id: session.client_id.clone(),
                    server_id: group_index as u32,
                    bucket_key: proto_bucket_keys,
                });
        
                let response = client.pir_query(request).await?;
                Ok::<_, Box<dyn Error>>(response.into_inner())
            };
            server_futures.push(client_future);
        }
    }

    let mut answers = Vec::new();
    for future in server_futures {
        let answer = future.await?;
        answers.push(answer);
    }

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

    let final_slots = dmpf_pir_reconstruct_servers::<ENTRY_U64_COUNT>(
        &all_server_results,
        session.num_buckets as usize,
    );

    let mut query_result = None;
    let bucket_size = session.bucket_size as usize;
    let bucket_to_global_index = global_indexes.iter().map(|&global_idx| {
        let bucket_idx = global_idx / bucket_size;
        (bucket_idx, global_idx)
    }).collect::<Vec<_>>();
    
    for (bucket_idx, slot) in final_slots.iter().enumerate() {
        let global_index = bucket_to_global_index.iter()
            .find(|&&(bucket, _)| bucket == bucket_idx)
            .map(|&(_, global_idx)| global_idx);
            
        match cuckoo_lib::decode_entry(slot) {
            Ok(Some((key, value))) => {
                if key == input_query_key && global_index.is_some() {
                    query_result = Some((global_index.unwrap(), value, slot.clone()));
                }
            },
            _ => {}
        }
    }

    Ok(query_result)
}

async fn execute_private_update(
    session: &ClientSession,
    server_addrs: &[&str],
    global_idx: usize,
    old_entry: &[u64; ENTRY_U64_COUNT],
    input_query_key: &str,
    new_value: &str,
) -> Result<(), Box<dyn Error>> {
    let new_value = encode_entry::<ENTRY_U64_COUNT>(input_query_key, new_value).unwrap();

    let mut beta: Entry<ENTRY_U64_COUNT> = [0u64; ENTRY_U64_COUNT];
    for i in 0..ENTRY_U64_COUNT {
        beta[i] = new_value[i].wrapping_sub(old_entry[i]);
    }

    let aes = create_aes(&session.aes_key);
    let (key0, key1) = dpf_gen_bytes::<ENTRY_U64_COUNT>(global_idx as u32, beta, session.n_bits as usize, &session.hash_key, &aes);

    let key0 = Arc::new(key0);
    let key1 = Arc::new(key1);

    let mut server_futures = Vec::new();

    for (_group_index, addr_chunk) in server_addrs.chunks(2).enumerate() {
        for (server_index, &addr) in addr_chunk.iter().enumerate() {
            let key0 = Arc::clone(&key0);
            let key1 = Arc::clone(&key1);
            
            let client_future = async move {
                let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await?;
                let key = if server_index == 0 {
                    (*key0).clone()
                } else {
                    (*key1).clone()
                };

                let cwn = dpf_key_bytes::Cwn {
                    hcw: key.cw_n.0.to_vec(),
                    lcw0: key.cw_n.1 as u32,
                    lcw1: key.cw_n.2 as u32,
                };

                let proto_key = DpfKeyBytes {
                    n: key.n as u32,
                    seed: key.seed.to_vec(),
                    cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                    cw_n: Some(cwn),
                    cw_np1: key.cw_np1.to_vec(),
                };

                let request = tonic::Request::new(PrivUpdateRequest {
                    client_id: session.client_id.clone(),
                    server_id: server_index as u32,
                    update_key: Some(proto_key),
                });

                let response = client.private_update(request).await?;
                Ok::<_, Box<dyn Error>>(response)
            };
            server_futures.push(client_future);
        }
    }

    let mut responses = Vec::new();
    for future in server_futures {
        let response = future.await?;
        responses.push(response);
    }

    Ok(())
}

async fn setup_benchmark_session() -> ClientSession {
    initialize_session(&DEFAULT_SERVERS).await.expect("Failed to initialize session")
}

fn bench_dpf_key_generation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("DPF Key Generation (Private Update)");
    group.measurement_time(Duration::from_secs(10));
    
    let test_keys = ["key5000"];
    
    for key in test_keys.iter() {
        group.bench_with_input(BenchmarkId::new("key_gen", key), key, |b, &query_key| {
            b.iter(|| {
                let global_indexes = get_hierarchical_indices(
                    &session.bucket_selection_key,
                    &session.local_hash_keys,
                    &session.local_hash_keys.len(),
                    &(session.num_buckets as usize),
                    &(session.bucket_size as usize),
                    query_key
                );
                
                let beta = 1;
                let target_points: Vec<(u32, u32)> = global_indexes.iter()
                    .map(|x| (*x as u32, beta))
                    .collect();
                
                let aes = create_aes(&session.aes_key);
                black_box(dmpf_pir_query_gen(
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
    
    let mut group = c.benchmark_group("Server Response Times (Private Update)");
    group.measurement_time(Duration::from_secs(10));
    
    let test_keys = ["key5000"];
    
    for key in test_keys.iter() {
        group.bench_with_input(BenchmarkId::new("server_response", key), key, |b, &query_key| {
            b.iter(|| {
                rt.block_on(async {
                    black_box(execute_pir_query(
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
    
    let mut group = c.benchmark_group("Individual Server Response Times (Private Update)");
    group.measurement_time(Duration::from_secs(10));
    
    let test_keys = ["key5000"];
    
    for (group_idx, addr_chunk) in DEFAULT_SERVERS.chunks(2).enumerate() {
        for (server_idx, &addr) in addr_chunk.iter().enumerate() {
            for key in test_keys.iter() {
                let bench_id = format!("server_{}_{}_response", group_idx, server_idx);
                group.bench_with_input(BenchmarkId::new(bench_id, key), key, |b, &query_key| {
                    b.iter(|| {
                        rt.block_on(async {
                            let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await.expect("Failed to connect");
                            
                            let global_indexes = get_hierarchical_indices(
                                &session.bucket_selection_key,
                                &session.local_hash_keys,
                                &session.local_hash_keys.len(),
                                &(session.num_buckets as usize),
                                &(session.bucket_size as usize),
                                query_key
                            );
                            
                            let beta = 1;
                            let target_points: Vec<(u32, u32)> = global_indexes.iter()
                                .map(|x| (*x as u32, beta))
                                .collect();
                            
                            let aes = create_aes(&session.aes_key);
                            let client_keys = dmpf_pir_query_gen(
                                &target_points,
                                session.num_buckets as usize,
                                session.bucket_size as usize,
                                session.bucket_bits,
                                &session.hash_key,
                                &aes
                            );
                            
                            let client_keys_for_server = &client_keys[group_idx];
                            let proto_bucket_keys = client_keys_for_server.iter().map(|key| {
                                let cwn = dpf_key::Cwn {
                                    hcw: key.cw_n.0.to_vec(),
                                    lcw0: key.cw_n.1 as u32,
                                    lcw1: key.cw_n.2 as u32,
                                };
                                
                                DpfKey {
                                    n: key.n as u32,
                                    seed: key.seed.to_vec(),
                                    cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                                    cw_n: Some(cwn),
                                    cw_np1: key.cw_np1,
                                }
                            }).collect();

                            let request = tonic::Request::new(BucketKeys {
                                client_id: session.client_id.clone(),
                                server_id: group_idx as u32,
                                bucket_key: proto_bucket_keys,
                            });

                            black_box(client.pir_query(request).await)
                        })
                    });
                });
            }
        }
    }
    group.finish();
}

fn bench_private_update(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("Private Update");
    group.measurement_time(Duration::from_secs(10));
    
    let test_keys = ["key5000"];
    
    for key in test_keys.iter() {
        group.bench_with_input(BenchmarkId::new("private_update", key), key, |b, &query_key| {
            b.iter(|| {
                rt.block_on(async {
                    // First get the current value and global index
                    let query_result = execute_pir_query(&session, &DEFAULT_SERVERS, query_key).await.expect("Query failed");
                    if let Some((global_idx, _, old_entry)) = query_result {
                        black_box(execute_private_update(
                            &session,
                            &DEFAULT_SERVERS,
                            global_idx,
                            &old_entry,
                            query_key,
                            "new_value_for_benchmark"
                        ).await)
                    } else {
                        // If key not found, return Ok(()) to maintain the Result type
                        Ok(())
                    }
                })
            });
        });
    }
    group.finish();
}

fn bench_reconstruction(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let session = rt.block_on(setup_benchmark_session());
    
    let mut group = c.benchmark_group("Reconstruction Time (Private Update)");
    group.measurement_time(Duration::from_secs(10));
    
    let test_keys = ["key5000"];
    
    for key in test_keys.iter() {
        let all_server_results = rt.block_on(async {
            let mut results = Vec::new();
            for (group_idx, addr_chunk) in DEFAULT_SERVERS.chunks(2).enumerate() {
                for (_, &addr) in addr_chunk.iter().enumerate() {
                    let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await.expect("Failed to connect");
                    
                    let global_indexes = get_hierarchical_indices(
                        &session.bucket_selection_key,
                        &session.local_hash_keys,
                        &session.local_hash_keys.len(),
                        &(session.num_buckets as usize),
                        &(session.bucket_size as usize),
                        key
                    );
                    
                    let beta = 1;
                    let target_points: Vec<(u32, u32)> = global_indexes.iter()
                        .map(|x| (*x as u32, beta))
                        .collect();
                    
                    let aes = create_aes(&session.aes_key);
                    let client_keys = dmpf_pir_query_gen(
                        &target_points,
                        session.num_buckets as usize,
                        session.bucket_size as usize,
                        session.bucket_bits,
                        &session.hash_key,
                        &aes
                    );
                    
                    let client_keys_for_server = &client_keys[group_idx];
                    let proto_bucket_keys = client_keys_for_server.iter().map(|key| {
                        let cwn = dpf_key::Cwn {
                            hcw: key.cw_n.0.to_vec(),
                            lcw0: key.cw_n.1 as u32,
                            lcw1: key.cw_n.2 as u32,
                        };
                        
                        DpfKey {
                            n: key.n as u32,
                            seed: key.seed.to_vec(),
                            cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                            cw_n: Some(cwn),
                            cw_np1: key.cw_np1,
                        }
                    }).collect();

                    let request = tonic::Request::new(BucketKeys {
                        client_id: session.client_id.clone(),
                        server_id: group_idx as u32,
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
            }
            results
        });

        group.bench_with_input(BenchmarkId::new("reconstruction", key), key, |b, _| {
            b.iter(|| {
                black_box(dmpf_pir_reconstruct_servers::<ENTRY_U64_COUNT>(
                    &all_server_results,
                    session.num_buckets as usize,
                ));
            });
        });
    }
    group.finish();
}

criterion_group! {
    name = benches_priv_upt;
    config = Criterion::default();
    targets = bench_dpf_key_generation,
             //bench_server_response_times,
             bench_individual_server_response_times,
             bench_private_update,
             bench_reconstruction
}
criterion_main!(benches_priv_upt); 