#!/usr/bin/env python3
import argparse
import csv
import base64
import hashlib
from multiprocessing import Pool, cpu_count

from faker import Faker
import pgpy
from pgpy.constants import (
    PubKeyAlgorithm, KeyFlags, HashAlgorithm,
    SymmetricKeyAlgorithm, CompressionAlgorithm, EllipticCurveOID
)

# 1) One global Faker instance, seeded once for reproducibility
faker = Faker()
faker.seed_instance(42)
faker.unique.clear() 

def make_keypair(email, algo_choice):
    if algo_choice == 1:
        algo, size = PubKeyAlgorithm.RSAEncryptOrSign, 2048
    elif algo_choice == 2:
        algo, size = PubKeyAlgorithm.RSAEncryptOrSign, 4096
    else:
        algo, size = PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519

    key = pgpy.PGPKey.new(algo, size)
    uid = pgpy.PGPUID.new(email)
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )
    return key

def worker(args):
    """Worker only sees (hashed_email, email, choice)"""
    hsh, email, choice = args
    key   = make_keypair(email, choice)
    pubb64 = base64.b64encode(key.pubkey.__bytes__()).decode()
    return hsh, pubb64

def main():
    p = argparse.ArgumentParser(description="Build email-hash → PGP binary key CSV.")
    p.add_argument("domain_size", type=int, help="number of entries (e.g. 2**20)")
    p.add_argument(
        "key_option", type=int, choices=[1, 2, 3],
        help="1=RSA-2048, 2=RSA-4096, 3=Curve25519 (Ed25519)"
    )
    p.add_argument("output_csv", help="CSV file path")
    p.add_argument(
        "--processes", "-p", type=int, default=cpu_count(),
        help="number of parallel workers (default: CPU count)"
    )
    args = p.parse_args()

    N, choice, num_procs = args.domain_size, args.key_option, args.processes
    checkpoint = max(1, N // 10)
    batch_size = 10_000

    # 2) Generate N *unique* emails up‐front in the main process
    print(f"Generating {N} unique emails…")
    emails = [faker.unique.email() for _ in range(N)]

    # 3) Build the list of tasks: (hash, email, choice)
    tasks = []
    for email in emails:
        hsh = hashlib.sha256(email.encode("utf-8")).hexdigest()
        tasks.append((hsh, email, choice))

    # 4) Dispatch to worker pool
    seen = set()
    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["key", "value"])

        with Pool(processes=num_procs) as pool:
            batch = []
            for i, (hsh, pubb64) in enumerate(
                pool.imap(worker, tasks, chunksize=1_000),
                start=1
            ):
                # (Optional) sanity‐check for duplicates
                if hsh in seen:
                    continue
                seen.add(hsh)

                batch.append((hsh, pubb64))

                if i % batch_size == 0:
                    w.writerows(batch)
                    f.flush()
                    batch.clear()

                if i % checkpoint == 0:
                    print(f"Progress: {int((i/N)*100)}% completed")

            # flush any leftovers
            if batch:
                w.writerows(batch)
                f.flush()

    print("Progress: 100% completed")

if __name__ == "__main__":
    main()
