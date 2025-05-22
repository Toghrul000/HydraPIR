# KPIR - Key-Value PIR Implementation

This project implements two Private Information Retrieval (PIR) schemes for key-value stores:
1. A basic scheme with non-private updates (kpir)
2. An advanced scheme with private updates (kpir_priv_upt)

## Prerequisites

- Rust and Cargo installed
- protoc for gRPC
- CSV file with key-value pairs for initialization

## Basic Scheme (kpir)

This scheme implements a PIR protocol with non-private updates. It requires 2 servers to operate.

### Available Commands

```bash
# Start a server
cargo run --release --bin kpir server <address:port>

# Run client
cargo run --release --bin kpir client -s <server1> <server2>

# Admin commands
# Initialize servers with data from CSV
cargo run --release --bin kpir admin init -s <server1> <server2> -f <csv_file>

# Insert a new key-value pair
cargo run --release --bin kpir admin insert -s <server1> <server2> -k <key> -v <value>
```

### Example Usage

1. Start two servers:
```bash
# Terminal 1
cargo run --release --bin kpir server 127.0.0.1:50051

# Terminal 2
cargo run --release --bin kpir server 127.0.0.1:50052
```

2. Initialize servers with data:
```bash
cargo run --release --bin kpir admin init -s 127.0.0.1:50051 127.0.0.1:50052 -f "./data/dummy_data_n_20.csv"
```

3. (Optional) Insert a new key-value pair:
```bash
cargo run --release --bin kpir admin insert -s 127.0.0.1:50051 127.0.0.1:50052 -k "new_key" -v "new_value"
```

4. Run the client to query data:
```bash
cargo run --release --bin kpir client -s 127.0.0.1:50051 127.0.0.1:50052
```

## Private Update Scheme (kpir_priv_upt)

This scheme implements an advanced PIR protocol with private updates. It requires a minimum of 4 servers to operate securely.

### Available Commands

```bash
# Start a server
cargo run --release --bin kpir_priv_upt server <address:port>

# Run client
cargo run --release --bin kpir_priv_upt client -s <server1> <server2> <server3> <server4>

# Admin command (initialize servers with data)
cargo run --release --bin kpir_priv_upt admin -s <server1> <server2> <server3> <server4> -f <csv_file>
```

### Example Usage

1. Start four servers:
```bash
# Terminal 1
cargo run --release --bin kpir_priv_upt server 127.0.0.1:50051

# Terminal 2
cargo run --release --bin kpir_priv_upt server 127.0.0.1:50052

# Terminal 3
cargo run --release --bin kpir_priv_upt server 127.0.0.1:50053

# Terminal 4
cargo run --release --bin kpir_priv_upt server 127.0.0.1:50054
```

2. Initialize servers with data:
```bash
cargo run --release --bin kpir_priv_upt admin -s 127.0.0.1:50051 127.0.0.1:50052 127.0.0.1:50053 127.0.0.1:50054 -f "./data/dummy_data_n_20.csv"
```

3. Run the client to query data:
```bash
cargo run --release --bin kpir_priv_upt client -s 127.0.0.1:50051 127.0.0.1:50052 127.0.0.1:50053 127.0.0.1:50054
```

## Help

For detailed help on any command, use the `--help` flag:
```bash
cargo run --bin kpir -- --help
cargo run --bin kpir server --help
cargo run --bin kpir admin --help
cargo run --bin kpir_priv_upt -- --help
```

## Benchmarks

This will run several benchmarks:
- DPF Key Generation: Measures the time to generate DPF keys
- Individual Server Response Times: Measures response time for each server separately
- Reconstruction Time: Measures the time to reconstruct the final result from server responses

### Running Individual Benchmarks
IMPORTANT: Before running benchmark commands you need have started servers and intialized them with data (Since bench client connects to those), look above on how to do that.

You can run specific benchmarks using the following commands:

For the Regular PIR scheme:
```bash
# Run all Regular PIR benchmarks
cargo bench --bench pir_benchmarks

# Run specific Regular PIR benchmarks
cargo bench --bench pir_benchmarks -- DPF\ Key\ Generation
cargo bench --bench pir_benchmarks -- Individual\ Server\ Response\ Times
cargo bench --bench pir_benchmarks -- Reconstruction\ Time
```

For the private update scheme:
```bash
# Run all private update benchmarks
cargo bench --bench pir_priv_upt_benchmarks

# Run specific private update benchmarks
cargo bench --bench pir_priv_upt_benchmarks -- DPF\ Key\ Generation\ \(Private\ Update\)
cargo bench --bench pir_priv_upt_benchmarks -- Individual\ Server\ Response\ Times\ \(Private\ Update\)
cargo bench --bench pir_priv_upt_benchmarks -- Private\ Update
cargo bench --bench pir_priv_upt_benchmarks -- Reconstruction\ Time\ \(Private\ Update\)
```

Note: The benchmarks use localhost servers by default:
- Regular PIR scheme: 127.0.0.1:50051 and 127.0.0.1:50052
- Private update scheme: 127.0.0.1:50051, 127.0.0.1:50052, 127.0.0.1:50053, and 127.0.0.1:50054

Make sure these servers are running before running the benchmarks.

The benchmark results will be displayed in the terminal and also saved in `target/criterion/`. 