use crate::ms_kpir::pir_service_client::PirServiceClient;
use crate::ms_kpir::Query;

pub async fn run_client(server_addrs: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
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
