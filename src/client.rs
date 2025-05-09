use crate::ms_kpir::pir_service_client::PirServiceClient;
use crate::ms_kpir::{Query, ClientSessionInitRequest};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::RngCore;
use uuid::Uuid;

#[derive(Clone)]
pub struct ClientSession {
    pub client_id: String,
    pub aes_key: [u8; 16],
    pub hash_key: [u8; 16],
    pub num_buckets: u32,
    pub bucket_size: u32,
    pub bucket_bits: u32,
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
        }
        
        println!("Initialized session with server at {}", addr);
    }
    
    println!("Client session initialized with ID: {}", client_id);
    println!("PIR parameters: num_buckets={}, bucket_size={}, bucket_bits={}", 
             session.num_buckets, session.bucket_size, session.bucket_bits);
    
    Ok(session)
}

pub async fn run_client(server_addrs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize client session
    let session = initialize_session(server_addrs).await?;
    
    let mut answers = Vec::new();

    for (i, &addr) in server_addrs.iter().enumerate() {
        let mut client = PirServiceClient::connect(format!("http://{}", addr)).await?;
        
        // TODO: Generate actual DPF key for each server using your DPF key generation function.
        // For now, we use a dummy query string converted to bytes.
        let dpf_key = format!("query for server {}", i + 1).into_bytes();
        
        let query = Query { dpf_key };
        let request = tonic::Request::new(query);
        let response = client.pir_query(request).await?;
        let answer = response.into_inner();
        answers.push(answer);
    }

    // TODO: Reconstruct the final result from answers using your DPF reconstruction function.
    for (i, answer) in answers.iter().enumerate() {
        println!("Answer from server {}: {:?}", i + 1, answer.data);
    }
    Ok(())
}
