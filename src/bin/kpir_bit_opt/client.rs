use crate::ms_kpir::bit_optimized_pir_service_client::BitOptimizedPirServiceClient;
use crate::ms_kpir::{BitDpfKey, BucketBitOptimizedKeys, ClientSessionInitRequest, CuckooKeys};
use crate::ms_kpir::bit_dpf_key;
use cuckoo_lib::get_hierarchical_indices;
use dpf_half_tree_bit_lib::{dmpf_bit_pir_query_gen, dmpf_bit_pir_reconstruct_servers};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use futures::future::join_all;
use uuid::Uuid;
use std::error::Error;
use std::io::{self, Write};
use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};

use kpir::config::ENTRY_U64_COUNT;
// const ENTRY_U64_COUNT: usize = 32; // 32 u64s = 256 bytes

#[derive(Clone)]
pub struct ClientSession {
    pub client_id: String,
    pub aes_key: [u8; 16],
    pub hs_key: [u8; 16],
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
        hs_key: hash_key,
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
            first_server_keys = Some((
                response_inner.local_hash_keys.clone(),
                response_inner.bucket_selection_key.clone()
            ));
            session.bucket_selection_key = response_inner.bucket_selection_key.try_into().unwrap();
            session.entry_u64_count = response_inner.entry_u64_count as usize;
        } else if i > 0 {
            // For subsequent servers, check if their keys are different from first server's keys
            if let Some((first_local_hash_keys, first_bucket_selection_key)) = &first_server_keys {
                // Check if either the local hash keys or bucket selection key is different
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
    
    let aes = create_aes(&session.aes_key);

    let client_keys = dmpf_bit_pir_query_gen(&target_points, session.num_buckets as usize, session.bucket_size as usize, session.bucket_bits, &session.hs_key, &aes);
    
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

    // // Wait for all server responses in parallel
    // let answers = join_all(server_futures).await
    //     .into_iter()
    //     .collect::<Result<Vec<_>, _>>()?;

    // Sequentially wait
    let mut answers = Vec::new();
    for future in server_futures {
        let answer = future.await?; 
        answers.push(answer);
    }

    // Convert the received answers to the format expected by dmpf_pir_reconstruct_servers
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
    println!("Reconstructed results per bucket:");
    
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
                println!("  Bucket {}: key=\"{}\", value=\"{}\"", bucket_idx, key, value);
                if key == input_query_key && global_index.is_some() {
                    query_result = Some((global_index.unwrap(), value, slot.clone()));
                }
            },
            Ok(None) => {
                println!("  Bucket {}: Empty slot", bucket_idx);
            },
            Err(e) => {
                println!("  Bucket {}: Error decoding: {:?}", bucket_idx, e);
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
        
        let cleanup_request = crate::ms_kpir::ClientCleanupRequest {
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

pub async fn run_client(server_addrs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client session
    let session = initialize_session(server_addrs).await?;

    loop {
        println!("\nChoose operation:");
        println!("1. PIR Query");
        println!("2. Exit");
        print!("Enter choice (1,2): ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read input");
        let choice = choice.trim();

        match choice {
            "1" => {
                print!("Enter key to query: ");
                io::stdout().flush().unwrap();
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read input");
                let input_query_key = input.trim();

                let query_result = execute_pir_query_and_display_results(&session, server_addrs, input_query_key).await;

                match query_result {
                    Ok(res) => {
                        if let Some((global_idx, value_string, _entry)) = res {
                            println!("Query key '{}' Value = {} found at global index: {}", input_query_key, value_string, global_idx);
                        } else {
                            println!("Query key not found in the DB");
                        }
                    },
                    Err(e) => eprintln!("Error: {}", e),
                }
            },
            "2" => {
                println!("Cleaning up client session before exit...");
                if let Err(e) = cleanup_client_session(&session, server_addrs).await {
                    eprintln!("Error during cleanup: {}", e);
                }
                println!("Exiting client...");
                break;
            },
            _ => println!("Invalid choice. Please enter 1 or 2."),
        }
    }

    Ok(())
}
