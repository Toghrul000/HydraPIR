use tonic::transport::Server;
use clap::{Parser, Subcommand};
mod client;
mod server;
mod server_admin;
use server::MyPIRService;
use crate::ms_kpir::bit_optimized_pir_service_server::BitOptimizedPirServiceServer;

pub mod ms_kpir {
    tonic::include_proto!("ms_kpir");
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a server instance
    Server {
        /// Server address (e.g., 127.0.0.1:50051)
        addr: String,
    },
    /// Run the client
    Client {
        /// Server addresses to connect to
        #[arg(short, long, num_args = 1.., required = true)]
        servers: Vec<String>,
    },
    /// Run the admin client
    Admin {
        #[command(subcommand)]
        action: AdminAction,
    },
}

#[derive(Subcommand)]
enum AdminAction {
    /// Initialize servers with data from a CSV file
    Init {
        /// Server addresses to connect to
        #[arg(short, long, num_args = 1.., required = true)]
        servers: Vec<String>,
        /// Path to the CSV file
        #[arg(short, long, required = true)]
        file: String,
    },
    /// Insert a new key-value pair
    Insert {
        /// Server addresses to connect to
        #[arg(short, long, num_args = 1.., required = true)]
        servers: Vec<String>,
        /// Key to insert
        #[arg(short, long, required = true)]
        key: String,
        /// Value to insert
        #[arg(short, long, required = true)]
        value: String,
    },
}

async fn run_server(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = addr.parse()?;
    let pir_service = MyPIRService::default();
    println!("Server listening on {}", addr);
    Server::builder()
        .add_service(BitOptimizedPirServiceServer::new(pir_service))
        .serve(addr)
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { addr } => {
            run_server(&addr).await?;
        }
        Commands::Client { servers } => {
            let server_refs: Vec<&str> = servers.iter().map(|s| s.as_str()).collect();
            client::run_client(&server_refs).await?;
        }
        Commands::Admin { action } => {
            match action {
                AdminAction::Init { servers, file } => {
                    server_admin::run_admin_client(&file, &servers).await?;
                }
                AdminAction::Insert { servers, key, value } => {
                    server_admin::update_servers(key, value, &servers).await?;
                }
            }
        }
    }
    Ok(())
}
