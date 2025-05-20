use std::env;
use tonic::transport::Server;
mod client;
mod server;
mod server_admin;
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
            // Connect to two servers running on ports 50051 and 50052.
            let server_addrs = ["127.0.0.1:50051", "127.0.0.1:50052"];
            client::run_client(&server_addrs).await?;
        }
        "admin" => {
            // Connect to two servers running on ports 50051 and 50052.
            let server_addrs = ["127.0.0.1:50051", "127.0.0.1:50052"];
            let server_addrs: Vec<String> = server_addrs.iter().map(|&s| s.to_string()).collect();
            
            // Check if we're doing an insert operation
            if args.len() >= 3 && args[2] == "-i" {
                let mut key = String::new();
                let mut value = String::new();
                
                // Parse key and value from arguments
                let mut i = 3;
                while i < args.len() {
                    match args[i].as_str() {
                        "-k" => {
                            if i + 1 < args.len() {
                                key = args[i + 1].clone();
                                i += 2;
                            } else {
                                eprintln!("Missing value for -k parameter");
                                return Ok(());
                            }
                        },
                        "-v" => {
                            if i + 1 < args.len() {
                                value = args[i + 1].clone();
                                i += 2;
                            } else {
                                eprintln!("Missing value for -v parameter");
                                return Ok(());
                            }
                        },
                        _ => {
                            i += 1;
                        }
                    }
                }
                
                if key.is_empty() {
                    eprintln!("Key parameter (-k) is required");
                    return Ok(());
                }
                
                if value.is_empty() {
                    eprintln!("Value parameter (-v) is required");
                    return Ok(());
                }
                
                server_admin::update_servers(key, value, &server_addrs).await?;
            } else {
                server_admin::run_admin_client("./data/dummy_data.csv", &server_addrs).await?;
            }
        }
        _ => {
            eprintln!("Invalid command: {}", args[1]);
        }
    }
    Ok(())
}
