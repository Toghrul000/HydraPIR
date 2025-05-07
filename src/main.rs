use std::env;
use tonic::transport::Server;
mod client;
mod server;
use server::MyPIRService;
use crate::ms_kpir::pir_service_server::PirServiceServer;

pub mod ms_kpir {
    tonic::include_proto!("ms_kpir");
}

async fn run_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let pir_service = MyPIRService::default();
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(PirServiceServer::new(pir_service))
        .serve(addr)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [server <port>|client]", args[0]);
        return Ok(());
    }
    match args[1].as_str() {
        "server" => {
            if args.len() != 3 {
                eprintln!("Usage: {} server <port>", args[0]);
                return Ok(());
            }
            let addr = format!("127.0.0.1:{}", args[2]);
            run_server(&addr).await?;
        }
        "client" => {
            // Connect to two servers running on ports 50051 and 50052.
            let server_addrs = ["127.0.0.1:50051", "127.0.0.1:50052"];
            client::run_client(&server_addrs).await?;
        }
        _ => {
            eprintln!("Invalid command: {}", args[1]);
        }
    }
    Ok(())
}
