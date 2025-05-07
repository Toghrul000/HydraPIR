use tonic::{Request, Response, Status};
use crate::ms_kpir::{Query, Answer};
use crate::ms_kpir::pir_service_server::PirService;

#[derive(Debug, Default)]
pub struct MyPIRService {}

#[tonic::async_trait]
impl PirService for MyPIRService {
    async fn pir_query(
        &self,
        request: Request<Query>,
    ) -> Result<Response<Answer>, Status> {
        let query = request.into_inner();
        println!("Received query with dpf_key: {:?}", query.dpf_key);
        
        // TODO: Process the DPF key and perform the PIR query on the server's database.
        // For now, simply return a dummy answer.
        let data = b"dummy answer".to_vec();
        let answer = Answer { data };

        Ok(Response::new(answer))
    }
}
