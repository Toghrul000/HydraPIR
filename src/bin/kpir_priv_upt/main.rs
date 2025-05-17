use std::env;
use tonic::transport::Server;
mod client;
mod server;
mod server_admin;
use server::MyPIRService;
use crate::ms_kpir::pir_service_private_update_server::PirServicePrivateUpdateServer;

pub mod ms_kpir {
    tonic::include_proto!("ms_kpir");
}

async fn run_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let pir_service = MyPIRService::default();
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(PirServicePrivateUpdateServer::new(pir_service))
        .serve(addr)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [server <port>|client|admin]", args[0]);
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
            // Connect to two servers running on ports
            let server_addrs = ["127.0.0.1:50051", "127.0.0.1:50052", "127.0.0.1:50053", "127.0.0.1:50054"];
            client::run_client(&server_addrs).await?;
        }
        "admin" => {
            // Connect to two servers running on ports
            let server_addrs = ["127.0.0.1:50051", "127.0.0.1:50052", "127.0.0.1:50053", "127.0.0.1:50054"];
            let server_addrs: Vec<String> = server_addrs.iter().map(|&s| s.to_string()).collect();
            server_admin::run_admin_client("dummy_data.csv", &server_addrs).await?;
            
        }
        _ => {
            eprintln!("Invalid command: {}", args[1]);
        }
    }
    Ok(())
}
