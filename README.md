# KPIR - Key-Value PIR Implementation

This project implements four Private Information Retrieval (PIR) schemes for key-value stores:

1. A regular scheme with non-private updates (kpir)
2. An advanced scheme with private updates (kpir_priv_upt)
3. A bit-optimized regular scheme (kpir_bit_opt)
4. A bit-optimized scheme with private updates (kpir_bit_opt_priv_upt)

## Prerequisites

- Rust and Cargo installed
- protoc for gRPC
- CSV file with key-value pairs for initialization (Should contain key, value header; dummy data can be generated with ./data/gen_db.py)

## Install `protoc` (Protocol Buffers Compiler)

#### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y protobuf-compiler
```

#### Windows (using Chocolatey)

```powershell
choco install protoc
```

## Quick Start

### Running Servers in Background

You can start all servers for a scheme in the background with a single command:

```bash
# For regular or regular scheme (2 servers)
cargo run --release --bin kpir server 127.0.0.1:50051 & cargo run --release --bin kpir server 127.0.0.1:50052 & wait

# For private update scheme (4 servers)
cargo run --release --bin kpir_priv_upt server 127.0.0.1:50051 & cargo run --release --bin kpir_priv_upt server 127.0.0.1:50052 & cargo run --release --bin kpir_priv_upt server 127.0.0.1:50053 & cargo run --release --bin kpir_priv_upt server 127.0.0.1:50054 & wait
```

Bit-optimized versions of one liner:

```bash
# For regular or regular scheme (2 servers)
cargo run --release --bin kpir_bit_opt server 127.0.0.1:50051 & cargo run --release --bin kpir_bit_opt server 127.0.0.1:50052 & wait

# For private update scheme (4 servers)
cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50051 & cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50052 & cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50053 & cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50054 & wait
```

To manage background servers:
```bash
# List running servers
jobs

# Stop a specific server (replace %1 with the job number from jobs command)
kill %1

# Stop all servers
kill $(jobs -p)
```

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

## Bit-Optimized Regular Scheme (kpir_bit_opt)

This scheme implements a bit-optimized version of the regular PIR protocol with non-private updates. It requires 2 servers to operate.

### Available Commands

```bash
# Start a server
cargo run --release --bin kpir_bit_opt server <address:port>

# Run client
cargo run --release --bin kpir_bit_opt client -s <server1> <server2>

# Admin commands
# Initialize servers with data from CSV
cargo run --release --bin kpir_bit_opt admin init -s <server1> <server2> -f <csv_file>

# Insert a new key-value pair
cargo run --release --bin kpir_bit_opt admin insert -s <server1> <server2> -k <key> -v <value>
```

### Example Usage

1. Start two servers:

```bash
# Terminal 1
cargo run --release --bin kpir_bit_opt server 127.0.0.1:50051

# Terminal 2
cargo run --release --bin kpir_bit_opt server 127.0.0.1:50052
```

2. Initialize servers with data:

```bash
cargo run --release --bin kpir_bit_opt admin init -s 127.0.0.1:50051 127.0.0.1:50052 -f "./data/dummy_data_n_20.csv"
```

3. (Optional) Insert a new key-value pair:

```bash
cargo run --release --bin kpir_bit_opt admin insert -s 127.0.0.1:50051 127.0.0.1:50052 -k "new_key" -v "new_value"
```

4. Run the client to query data:

```bash
cargo run --release --bin kpir_bit_opt client -s 127.0.0.1:50051 127.0.0.1:50052
```

## Bit-Optimized Private Update Scheme (kpir_bit_opt_priv_upt)

This scheme implements a bit-optimized version of the advanced PIR protocol with private updates. It requires a minimum of 4 servers to operate securely.

### Available Commands

```bash
# Start a server
cargo run --release --bin kpir_bit_opt_priv_upt server <address:port>

# Run client
cargo run --release --bin kpir_bit_opt_priv_upt client -s <server1> <server2> <server3> <server4>

# Admin command (initialize servers with data)
cargo run --release --bin kpir_bit_opt_priv_upt admin -s <server1> <server2> <server3> <server4> -f <csv_file>
```

### Example Usage

1. Start four servers:

```bash
# Terminal 1
cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50051

# Terminal 2
cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50052

# Terminal 3
cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50053

# Terminal 4
cargo run --release --bin kpir_bit_opt_priv_upt server 127.0.0.1:50054
```

2. Initialize servers with data:

```bash
cargo run --release --bin kpir_bit_opt_priv_upt admin -s 127.0.0.1:50051 127.0.0.1:50052 127.0.0.1:50053 127.0.0.1:50054 -f "./data/dummy_data_n_20.csv"
```

3. Run the client to query data:

```bash
cargo run --release --bin kpir_bit_opt_priv_upt client -s 127.0.0.1:50051 127.0.0.1:50052 127.0.0.1:50053 127.0.0.1:50054
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

### Running Benchmarks

IMPORTANT: Before running benchmark commands you need have started servers and intialized them with data (Since bench client connects to those), look above on how to do that.

You can run benchmarks using the following commands:

For the Regular PIR scheme:
```bash
cargo bench --bench pir_benchmarks
```

For the private update scheme:
```bash
cargo bench --bench pir_priv_upt_benchmarks
```

For the Bit-Optimized Regular PIR scheme:
```bash
cargo bench --bench bit_pir_benchmarks
```

For the Bit-Optimized private update scheme:
```bash
cargo bench --bench bit_pir_priv_upt_benchmarks
```

Note: The benchmarks use localhost servers by default:

- Regular PIR scheme: 127.0.0.1:50051 and 127.0.0.1:50052
- Private update scheme: 127.0.0.1:50051, 127.0.0.1:50052, 127.0.0.1:50053, and 127.0.0.1:50054
- Bit-Optimized schemes use the same server addresses as their non-optimized counterparts

Make sure these servers are running before running the benchmarks.

The benchmark results will be displayed in the terminal and also saved in `target/criterion/`.
