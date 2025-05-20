use crate::ms_kpir::pir_service_private_update_client::PirServicePrivateUpdateClient;
use crate::ms_kpir::{dpf_key_bytes, BucketKeys, ClientSessionInitRequest, DpfKey, DpfKeyBytes, PrivUpdateRequest};
use crate::ms_kpir::dpf_key;
use cuckoo_lib::{encode_entry, get_hierarchical_indices, Entry};
use dpf_half_tree_lib::{dmpf_pir_query_gen, dmpf_pir_reconstruct_servers, dpf_gen_bytes};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use futures::future::join_all;
use std::sync::Arc;
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
    pub hash_key: [u8; 16],
    pub num_buckets: u32,
    pub bucket_size: u32,
    pub bucket_bits: u32,
    pub n_bits: u32,
    pub bucket_selection_key: [u8; 16], // Cuckoo bucket chosing key
    pub local_hash_keys: Vec<[u8; 16]>,  // Cuckoo hash keys from server
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
        n_bits: 0,
        bucket_selection_key: [0u8; 16],
        local_hash_keys: Vec::new(),
        entry_u64_count: 0,
        
    };
    
    // Send session init request to each server
    for &addr in server_addrs {
        let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await?;
        
        let init_request = ClientSessionInitRequest {
            client_id: client_id.clone(),
            aes_key: aes_key_bytes.to_vec(),
            hash_key: hash_key.to_vec(),
        };
        
        let response = client.init_client_session(tonic::Request::new(init_request)).await?;
        let response_inner = response.into_inner();
        
        // Only store the configuration parameters once (they should be the same from all servers)
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


async fn execute_pir_query_and_display_results(
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
    
    // Get AES instance - needed for the DPF
    let aes = create_aes(&session.aes_key);

    let client_keys = dmpf_pir_query_gen(&target_points, session.num_buckets as usize, session.bucket_size as usize, session.bucket_bits, &session.hash_key, &aes);
    
    let mut server_futures = Vec::new();

    for (group_index, addr_chunk) in server_addrs.chunks(2).enumerate() {
        for (_, &addr) in addr_chunk.iter().enumerate() {
            let client_keys_for_group = &client_keys[group_index];
            let client_future = async move {
                let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await?;
                
                // Use group_index to index client_keys
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

    // // Wait for all server responses in parallel
    // let answers = join_all(server_futures).await
    //     .into_iter()
    //     .collect::<Result<Vec<_>, _>>()?;

    // Sequentially wait
    let mut answers = Vec::new();
    for future in server_futures {
        let answer = future.await?;  // Propagate error if any
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

    // Run reconstruction
    let final_slots = dmpf_pir_reconstruct_servers::<ENTRY_U64_COUNT>(
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
                // Check if this is the key we queried for
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

    // Wrap the keys in Arc for shared ownership
    let key0 = Arc::new(key0);
    let key1 = Arc::new(key1);

    let mut server_futures = Vec::new();

    for (_group_index, addr_chunk) in server_addrs.chunks(2).enumerate() {
        for (server_index, &addr) in addr_chunk.iter().enumerate() {
            // Clone the Arc (cheap operation)
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

    // // Wait for all server responses in parallel
    // let responses = join_all(server_futures).await
    //     .into_iter()
    //     .collect::<Result<Vec<_>, _>>()?;

    // Sequentially wait
    let mut responses = Vec::new();

    for future in server_futures {
        // Await each future one at a time
        let response = future.await?;
        responses.push(response);
    }

    // Print responses
    for response in responses {
        println!("{:?}", response);
    }

    Ok(())
}


async fn cleanup_client_session(session: &ClientSession, server_addrs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Cleaning up client session...");
    
    for &addr in server_addrs {
        let mut client = PirServicePrivateUpdateClient::connect(format!("http://{}", addr)).await?;
        
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
        println!("2. Private Update");
        println!("3. Exit");
        print!("Enter choice (1-3): ");
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
                print!("Enter key to update: ");
                io::stdout().flush().unwrap();
                let mut key_input = String::new();
                io::stdin().read_line(&mut key_input).expect("Failed to read input");
                let key = key_input.trim();

                // First query to get current value and global index
                let query_result = execute_pir_query_and_display_results(&session, server_addrs, key).await;

                match query_result {
                    Ok(res) => {
                        if let Some((global_idx, current_value, old_entry)) = res {
                            println!("Current value for key '{}' is '{}' at global index: {}", key, current_value, global_idx);
                            
                            print!("Enter new value: ");
                            io::stdout().flush().unwrap();
                            let mut new_value_input = String::new();
                            io::stdin().read_line(&mut new_value_input).expect("Failed to read input");
                            let new_value = new_value_input.trim();

                            // Execute private update
                            match execute_private_update(&session, server_addrs, global_idx, &old_entry, key, new_value).await {
                                Ok(_) => println!("Successfully updated value for key '{}'", key),
                                Err(e) => eprintln!("Error during private update: {}", e),
                            }
                        } else {
                            println!("Cannot update: Key not found in the DB");
                        }
                    },
                    Err(e) => eprintln!("Error during query: {}", e),
                }
            },
            "3" => {
                println!("Cleaning up client session before exit...");
                if let Err(e) = cleanup_client_session(&session, server_addrs).await {
                    eprintln!("Error during cleanup: {}", e);
                }
                println!("Exiting client...");
                break;
            },
            _ => println!("Invalid choice. Please enter 1, 2, or 3."),
        }
    }

    Ok(())
}
