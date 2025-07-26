#!/usr/bin/env python3
import argparse
import math
import re
import sys
from typing import Tuple

SIZE_RE = re.compile(r"^\s*(\d+)\s*([kmgtpezy]?i?b?)?\s*$", re.IGNORECASE)
POWER_OF_TWO = {
    "": 1,
    "b": 1,
    "k": 10**3,
    "kb": 10**3,
    "m": 10**6,
    "mb": 10**6,
    "g": 10**9,
    "gb": 10**9,
    "t": 10**12,
    "tb": 10**12,
    "p": 10**15,
    "pb": 10**15,
    # Binary (IEC)
    "kib": 1024**1,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
    "pib": 1024**5,
}

def parse_size(s: str) -> int:
    """
    Parse a human-friendly size string like '16MiB', '4KB', '1024', '1g'.
    Defaults to bytes when no suffix is provided.
    """
    m = SIZE_RE.match(s)
    if not m:
        raise argparse.ArgumentTypeError(f"Invalid size: {s}")
    value = int(m.group(1))
    suffix = (m.group(2) or "").lower()
    if suffix not in POWER_OF_TWO:
        # handle single-letter IEC like 'k', 'm', 'g' but in binary if followed by 'i'
        if suffix.endswith('i'):
            suffix += 'b'
        else:
            suffix += 'b'
    if suffix not in POWER_OF_TWO:
        raise argparse.ArgumentTypeError(f"Unknown size suffix in: {s}")
    return value * POWER_OF_TWO[suffix]

def calculate_required_table_size(
    total_storage_bytes: int, entry_size_bytes: int
) -> Tuple[int, int]:
    """
    Calculates the largest possible power of 2 table size and the corresponding
    exponent n (where table_size = 2^n) that can fit within the given storage.
    """
    if entry_size_bytes == 0:
        print("Error: entry_size_bytes cannot be 0.", file=sys.stderr)
        return (0, 0)

    # Ensure entry_size_bytes is reasonable (e.g., >= 8 for u64 alignment)
    if entry_size_bytes < 8 or entry_size_bytes % 8 != 0:
        print(
            f"Warning: calculate_required_table_size called with entry_size_bytes {entry_size_bytes} "
            f"not multiple of 8. Result might be suboptimal.",
            file=sys.stderr,
        )

    max_entries_possible = total_storage_bytes // entry_size_bytes

    if max_entries_possible == 0:
        return (1, 0)

    n = int(math.floor(math.log2(max_entries_possible)))
    table_size = 2**n

    return (table_size, n)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute the largest power-of-two table size that fits into the provided storage."
    )
    parser.add_argument(
        "total_storage",
        type=parse_size,
        help="Total storage capacity (e.g. 1GiB, 512MiB, 4096). Defaults to bytes if no suffix.",
    )
    parser.add_argument(
        "entry_size",
        type=parse_size,
        help="Entry size (e.g. 32, 16B, 64, 128). Defaults to bytes if no suffix.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress warnings printed to stderr."
    )
    parser.add_argument(
        "--print-bytes",
        action="store_true",
        help="Also print how many bytes the chosen table will consume."
    )

    args = parser.parse_args()

    if args.quiet:
        # Redirect stderr to devnull
        sys.stderr = open("/dev/null", "w")

    table_size, n = calculate_required_table_size(args.total_storage, args.entry_size)

    if args.print_bytes and table_size > 0:
        used_bytes = table_size * args.entry_size
        print(f"{table_size} {n} {used_bytes}")
    else:
        print(f"n = {n} in 2^n = {table_size} entries")

if __name__ == "__main__":
    main()



# import math

# def calculate_pir_config(n: int, bucket_num_option: int) -> tuple[int, int, int, int]:
#     if n == 0:
#         raise ValueError("N must be greater than 0 to calculate PIR configuration.")

#     if bucket_num_option == 0 or (bucket_num_option & (bucket_num_option - 1)) != 0:
#         raise ValueError(f"BUCKET_NUM_OPTION ({bucket_num_option}) must be a power of 2.")

#     try:
#         db_size = 1 << n
#     except OverflowError:
#         raise OverflowError(f"N ({n}) is too large, 1 << N overflowed.")

#     sqrt_db_size = math.sqrt(db_size)
#     if not math.isfinite(sqrt_db_size):
#         raise ValueError(f"Square root calculation resulted in non-finite value for N={n}")

#     sqrt_db_floor = math.floor(sqrt_db_size)
#     max_k_float = sqrt_db_floor / n

#     if not math.isfinite(max_k_float):
#         raise ValueError(f"Max k calculation resulted in non-finite value for N={n}")

#     max_k_allowed = math.floor(max_k_float)

#     if max_k_allowed == 0:
#         if n > sqrt_db_floor:
#             print(f"Warning: For N={n}, even 1 bucket violates the condition ({n} > {sqrt_db_floor}). "
#                   f"Defaulting to 1 bucket anyway.")
#         base_num_buckets = 1
#     else:
#         # Find the largest power of 2 <= max_k_allowed
#         base_num_buckets = 1 << (max_k_allowed.bit_length() - 1)


#     num_buckets = base_num_buckets * bucket_num_option
#     if num_buckets > db_size:
#         max_feasible_option = db_size // base_num_buckets
#         valid_options = []
#         option = 1
#         while option <= max_feasible_option:
#             valid_options.append(str(option))
#             option *= 2
#         raise ValueError(
#             f"BUCKET_NUM_OPTION ({bucket_num_option}) results in too many buckets ({num_buckets}). "
#             f"Cannot have more buckets than database entries ({db_size}). "
#             f"Valid power-of-2 BUCKET_NUM_OPTION values for N={n} are: {', '.join(valid_options)}"
#         )

#     bucket_size = db_size // num_buckets
#     if bucket_size == 0 or (bucket_size & (bucket_size - 1)) != 0:
#         raise ValueError(
#             f"BUCKET_NUM_OPTION ({bucket_num_option}) results in bucket_size ({bucket_size}) "
#             f"that is not a power of 2. This occurs when num_buckets ({num_buckets}) doesn't divide "
#             f"db_size ({db_size}) into power-of-2 chunks. Try a different BUCKET_NUM_OPTION value."
#         )

#     bucket_bits = bucket_size.bit_length() - 1

#     return db_size, num_buckets, bucket_size, bucket_bits


# def calculate_required_table_size(
#     total_storage_bytes: int, entry_size_bytes: int
# ) -> tuple[int, int]:
#     """
#     Calculates the largest possible power of 2 table size and the corresponding
#     exponent n (where table_size = 2^n) that can fit within the given storage.

#     Args:
#         total_storage_bytes: The total desired storage capacity in bytes.
#         entry_size_bytes: The size of each entry in bytes.

#     Returns:
#         A tuple (table_size, n) where:
#         * table_size: The largest power of 2 number of slots that fits.
#         * n: The exponent such that table_size == 2^n.
#         Returns (0, 0) if entry_size_bytes is 0.
#         Returns (1, 0) if total_storage_bytes is 0 or insufficient for even 1 entry.
#     """
#     if entry_size_bytes == 0:
#         print("Error: entry_size_bytes cannot be 0.", file=math.stderr)
#         return (0, 0)

#     # Ensure entry_size_bytes is reasonable (e.g., >= 8 for u64 alignment)
#     if entry_size_bytes < 8 or entry_size_bytes % 8 != 0:
#         print(
#             f"Warning: calculate_required_table_size called with entry_size_bytes {entry_size_bytes} not multiple of 8. Result might be suboptimal.",
#             file=math.stderr,
#         )

#     # Calculate the maximum number of entries that can fit
#     max_entries_possible = total_storage_bytes // entry_size_bytes

#     if max_entries_possible == 0:
#         return (1, 0)

#     # Find the largest power of 2 that is less than or equal to max_entries_possible.
#     # This represents the largest 2^n domain that can fit within the storage.
#     # This can be done by taking the floor of the log base 2 and then raising 2 to that power.
#     # In Python, we can use bit manipulation to find the most significant bit.
#     # Or use math.log2 and floor.
#     # A common way to find the largest power of 2 less than or equal to x is 2**(floor(log2(x))).
#     # If x is already a power of 2, floor(log2(x)) is log2(x).
#     # If x is not a power of 2, floor(log2(x)) gives the exponent of the largest power of 2 below x.

#     n = int(math.floor(math.log2(max_entries_possible)))
#     table_size = 2**n

#     return (table_size, n)





# # we need at least 256 MB for 2^20 * 256 B entries
# print(calculate_required_table_size(256 * 1024 * 1024, 256))  # 2^20 * 256 B entries

# # we need at least 3840 MB for 2^17 * 30kB entries
# print(calculate_required_table_size(3840 * 1024 * 1024, 30720))  # 2^17 * 30kB entries

# print(calculate_required_table_size(1920 * 1024 * 1024, 30720))  # 2^16 * 30kB entries

# # we need at least around 1,562.5 MB so 2 GB is also good for 2^14 * 100kB entries
# print(calculate_required_table_size(2 * 1024 * 1024 * 1024, 100000))  # 2^14 * 100kB entries
