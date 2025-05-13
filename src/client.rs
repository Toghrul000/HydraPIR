use crate::ms_kpir::pir_service_client::PirServiceClient;
use crate::ms_kpir::{ClientSessionInitRequest, BucketKeys, DpfKey};
use crate::ms_kpir::dpf_key;
use cuckoo_lib::get_hierarchical_indices;
use dpf_half_tree_lib::{dmpf_pir_query_gen, dmpf_pir_reconstruct_servers};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use uuid::Uuid;
use std::io::{self, Write};
use aes::Aes128;
use aes::cipher::{KeyInit, generic_array::GenericArray};

// Define entry size constant - must match server's ENTRY_U64_COUNT
const ENTRY_U64_COUNT: usize = 32; // 32 u64s = 256 bytes

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
    for &addr in server_addrs {
        let mut client = PirServiceClient::connect(format!("http://{}", addr)).await?;
        
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

pub async fn run_client(server_addrs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client session
    let session = initialize_session(server_addrs).await?;

    loop {
        print!("PIR QUERY: ");
        io::stdout().flush().unwrap(); // Make sure the prompt prints before input

        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read input");
        let input_query_key = input.trim(); 
        
        if input_query_key.trim().to_lowercase() == "exit" {
            println!("Exiting client...");
            break;
        }

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
        
        let mut answers = Vec::new();

        for (i, &addr) in server_addrs.iter().enumerate() {
            let mut client = PirServiceClient::connect(format!("http://{}", addr)).await?;
            
            // Convert Rust DPFKey to protobuf DPFKey
            let proto_bucket_keys = client_keys[i].iter().map(|key| {
                // Try with just the struct name, let Rust use the import correctly
                let cwn = dpf_key::Cwn {
                    hcw: key.cw_n.0.to_vec(),
                    lcw0: key.cw_n.1 as u32,
                    lcw1: key.cw_n.2 as u32,
                };
                
                // Create the DPFKey
                DpfKey {
                    n: key.n as u32,
                    seed: key.seed.to_vec(),
                    cw_levels: key.cw_levels.iter().map(|level| level.to_vec()).collect(),
                    cw_n: Some(cwn),
                    cw_np1: key.cw_np1,
                }
            }).collect();

            // Create BucketKeys request
            let request = tonic::Request::new(BucketKeys {
                client_id: session.client_id.clone(),
                server_id: i as u32,
                bucket_key: proto_bucket_keys,
            });

            let response = client.pir_query(request).await?;
            let answer = response.into_inner();
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
        println!("Reconstructed results per bucket:");
        for (bucket_idx, slot) in final_slots.iter().enumerate() {
            // Use the decode_entry from cuckoo_lib to decode the entry
            match cuckoo_lib::decode_entry(slot) {
                Ok(Some((key, value))) => {
                    println!("  Bucket {}: key=\"{}\", value=\"{}\"", bucket_idx, key, value);
                },
                Ok(None) => {
                    println!("  Bucket {}: Empty slot", bucket_idx);
                },
                Err(e) => {
                    println!("  Bucket {}: Error decoding: {:?}", bucket_idx, e);
                }
            }
        }

    }

    Ok(())
}
