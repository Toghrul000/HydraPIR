use tonic::transport::Server;
use clap::{Parser, Subcommand};
mod client;
mod server;
mod server_admin;
use server::MyPIRService;
use crate::ms_kpir::pir_service_private_update_server::PirServicePrivateUpdateServer;

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
        /// Server addresses to connect to
        #[arg(short, long, num_args = 1.., required = true)]
        servers: Vec<String>,
        /// Path to the CSV file
        #[arg(short, long, required = true)]
        file: String,
    },
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
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { addr } => {
            run_server(&addr).await?;
        }
        Commands::Client { servers } => {
            let server_refs: Vec<&str> = servers.iter().map(|s| s.as_str()).collect();
            client::run_client(&server_refs).await?;
        }
        Commands::Admin { servers, file } => {
            server_admin::run_admin_client(&file, &servers).await?;
        }
    }
    Ok(())
}
