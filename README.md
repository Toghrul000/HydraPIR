# MS KPIR - Multi Server Key-Value PIR Implementation

> **Recommended:**  
> For most users, we recommend using the **bit-optimized versions** of the schemes, as they are more performant.  
> - [Bit-Optimized Regular Scheme](#bit-optimized-regular-scheme-kpir_bit_opt)
> - [Bit-Optimized Private Update Scheme](#bit-optimized-private-update-scheme-kpir_bit_opt_priv_upt)

This project implements four Multi Server Private Information Retrieval (PIR) schemes for key-value stores:

1. A regular scheme with non-private updates (`kpir`)
2. An advanced scheme with private updates (`kpir_priv_upt`)
3. A bit-optimized regular scheme (`kpir_bit_opt`) - **[Recommended, see details](#bit-optimized-regular-scheme-kpir_bit_opt)**
4. A bit-optimized scheme with private updates (`kpir_bit_opt_priv_upt`) - **[Recommended, see details](#bit-optimized-private-update-scheme-kpir_bit_opt_priv_upt)**

---

## Project Structure

| Folder/File                | Description |
|----------------------------|-------------|
| `benches/`                 | Benchmark code (uses localhost by default; change IPs in bench files for remote) |
| `cuckoo_lib/`              | Encode/decode functions for key-value strings to integer arrays. Contains `CuckooHashTableBucketed` (main), `CuckooHashTableBucketedAdditiveShare` (for 4-server version), and legacy `CuckooHashTable` (reference which we improved upon). |
| `data/`                    | Benchmark result files and helper Python scripts for generating dummy data and testing configuration values. |
| `dpf_half_tree_lib/`       | Implementation of the Half-Tree DPF from: Xiaojie Guo et al., EUROCRYPT 2023 ([paper link](https://doi.org/10.1007/978-3-031-30545-0_12)). |
| `dpf_half_tree_bit_lib/`   | Bit-optimized version of the Half-Tree DPF implementation. |
| `proto/`                   | Protocol buffer files; the foundation for all schemes. |
| `src/`                     | Source files for the regular scheme. |
| `src/bin/kpir_bit_opt/`    | Source files for the bit-optimized regular scheme. |
| `src/bin/kpir_priv_upt/`   | Source files for the four-server scheme with private updates. |
| `src/bin/kpir_bit_opt_priv_upt/` | Source files for the bit-optimized private update scheme. |
| `.env` / `.example_env`    | Environment file for database/configuration and example env of how to write real env. |
| `build.rs`                 | Builds proto files and parses env file to make constants available at runtime. |

---

## Setting Up Entry Size, Dummy Data, and Environment

- **Entry Size & Storage:**  
  Set `KPIR_STORAGE_MB` (in MB) and `KPIR_ENTRY_SIZE_BYTES` (in bytes) in your `.env` file.  
  _Example: For 5 GiB storage and 1024B entry size:_  
  ```
  KPIR_STORAGE_MB=5120
  KPIR_ENTRY_SIZE_BYTES=1024
  ```
  > **Note:** Entry size should be divisible by 8.

- **Testing Table Size:**  
  To see how many entries fit:
  ```
  python3 ./data/config_tester.py 5120MiB 1024B
  # Output: n = 22 in 2^n = 4194304 entries
  ```

- **Testing Required Storage for a Table Size:**  
  ```
  python3 ./data/config_helper.py 20 256
  # Output: Table size: 2^20 = 1048576 entries, Entry size: 256 bytes, Required storage: 256 MB
  ```

- **Environment Parsing:**  
  The `build.rs` script parses your env file and makes these values available as constants at runtime.  
  If you change the env file and the changes are not picked up, try clearing the build cache.

- **IMPORTANT:**  
  The encode/decode functions in `cuckoo_lib` add a 16-byte overhead to each entry.  
  If you set `KPIR_ENTRY_SIZE_BYTES=1024`, your actual key+value in the CSV should be ≤1008 bytes.

## More ENV Configuration parameters

The following environment variables control the behavior of the cuckoo hash table used for storing key-value pairs:

- **`KPIR_MAX_REHASH_ATTEMPTS`:**  
  Maximum number of rehash attempts before increasing the number of hash functions.  
  If the dataset does not fit in the cuckoo hash table, the table rehashes with new hash function keys.  
  If it fails again, it tries repeatedly. This parameter controls how many rehash attempts are made before increasing the number of hash functions and trying again.  

  _Default: 2_

- **`BUCKET_NUM_OPTION`:**  
  Controls the number of buckets generated for the database size.  
  - Default value is 1 (normal bucket count)
  - Set to 2 to double the number of buckets
  - Set to 4 to quadruple the number of buckets
  - Must be a power of 2 (1, 2, 4, 8, 16, etc.)

  _Default: 1_

---

## ⚠️ Slow Compile Time

Compile times are slower than normal because the code is optimized for runtime performance.  
We added flags in `Cargo.toml` for production builds.

---

## Notes for Repurposing for future

1. **Encode/Decode Overhead:**  
   The current encode/decode functions are generic and add a 16-byte overhead to support arbitrary string sizes.  
   If you only need to support smaller entries, you can modify these functions in `cuckoo_lib` to reduce the overhead (e.g., to 4 bytes).

2. **Async Client Requests:**  
   All clients currently wait for each server response sequentially (to measure response times accurately on localhost, since we run all servers in the same machine).  
   In real-world deployments, we have servers in different machines. Thus, you should send requests in parallel.  
   See the commented-out code in the client:
   ```rust
   // // Wait for all server responses in parallel
   // let answers = join_all(server_futures).await
   //     .into_iter()
   //     .collect::<Result<Vec<_>, _>>()?;

   // Sequentially wait
   let mut answers = Vec::new();
   for future in server_futures {
       let answer = future.await?;  
       answers.push(answer);
   }
   ```
   Replace the sequential loop with `join_all` for parallel requests in environment where servers are deployed to different machines.

---

## Main Prerequisites

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

# Update an existing key-value pair (use --upsert to insert if key doesn't exist)
cargo run --release --bin kpir admin update -s <server1> <server2> -k <key> -v <value> [--upsert]

# Delete a key from servers
cargo run --release --bin kpir admin delete -s <server1> <server2> -k <key>
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

4. (Optional) Update an existing key-value pair:

```bash
cargo run --release --bin kpir admin update -s 127.0.0.1:50051 127.0.0.1:50052 -k "existing_key" -v "updated_value"
```

5. (Optional) Update with upsert (insert if key doesn't exist):

```bash
cargo run --release --bin kpir admin update -s 127.0.0.1:50051 127.0.0.1:50052 -k "maybe_existing_key" -v "new_or_updated_value" --upsert
```

6. (Optional) Delete a key:

```bash
cargo run --release --bin kpir admin delete -s 127.0.0.1:50051 127.0.0.1:50052 -k "new_key"
```

7. Run the client to query data:

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

# Update an existing key-value pair (use --upsert to insert if key doesn't exist)
cargo run --release --bin kpir_bit_opt admin update -s <server1> <server2> -k <key> -v <value> [--upsert]

# Delete a key from servers
cargo run --release --bin kpir_bit_opt admin delete -s <server1> <server2> -k <key>
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

4. (Optional) Update an existing key-value pair:

```bash
cargo run --release --bin kpir_bit_opt admin update -s 127.0.0.1:50051 127.0.0.1:50052 -k "existing_key" -v "updated_value"
```

5. (Optional) Update with upsert (insert if key doesn't exist):

```bash
cargo run --release --bin kpir_bit_opt admin update -s 127.0.0.1:50051 127.0.0.1:50052 -k "maybe_existing_key" -v "new_or_updated_value" --upsert
```

6. (Optional) Delete a key:

```bash
cargo run --release --bin kpir_bit_opt admin delete -s 127.0.0.1:50051 127.0.0.1:50052 -k "new_key"
```

7. Run the client to query data:

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

For the Bit-Optimized non-private update operations:
```bash
cargo bench --bench non_priv_upt_benchmarks
```

Note: The benchmarks use localhost servers by default:

- Regular PIR scheme: 127.0.0.1:50051 and 127.0.0.1:50052
- Private update scheme: 127.0.0.1:50051, 127.0.0.1:50052, 127.0.0.1:50053, and 127.0.0.1:50054
- Bit-Optimized schemes use the same server addresses as their non-optimized counterparts

Make sure these servers are running before running the benchmarks.

The benchmark results will be displayed in the terminal and also saved in `target/criterion/`.
