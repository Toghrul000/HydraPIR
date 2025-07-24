import math


def calculate_required_table_size(
    total_storage_bytes: int, entry_size_bytes: int
) -> tuple[int, int]:
    """
    Calculates the largest possible power of 2 table size and the corresponding
    exponent n (where table_size = 2^n) that can fit within the given storage.

    Args:
        total_storage_bytes: The total desired storage capacity in bytes.
        entry_size_bytes: The size of each entry in bytes.

    Returns:
        A tuple (table_size, n) where:
        * table_size: The largest power of 2 number of slots that fits.
        * n: The exponent such that table_size == 2^n.
        Returns (0, 0) if entry_size_bytes is 0.
        Returns (1, 0) if total_storage_bytes is 0 or insufficient for even 1 entry.
    """
    if entry_size_bytes == 0:
        print("Error: entry_size_bytes cannot be 0.", file=math.stderr)
        return (0, 0)

    # Ensure entry_size_bytes is reasonable (e.g., >= 8 for u64 alignment)
    if entry_size_bytes < 8 or entry_size_bytes % 8 != 0:
        print(
            f"Warning: calculate_required_table_size called with entry_size_bytes {entry_size_bytes} not multiple of 8. Result might be suboptimal.",
            file=math.stderr,
        )

    # Calculate the maximum number of entries that can fit
    max_entries_possible = total_storage_bytes // entry_size_bytes

    if max_entries_possible == 0:
        return (1, 0)

    # Find the largest power of 2 that is less than or equal to max_entries_possible.
    # This represents the largest 2^n domain that can fit within the storage.
    # This can be done by taking the floor of the log base 2 and then raising 2 to that power.
    # In Python, we can use bit manipulation to find the most significant bit.
    # Or use math.log2 and floor.
    # A common way to find the largest power of 2 less than or equal to x is 2**(floor(log2(x))).
    # If x is already a power of 2, floor(log2(x)) is log2(x).
    # If x is not a power of 2, floor(log2(x)) gives the exponent of the largest power of 2 below x.

    n = int(math.floor(math.log2(max_entries_possible)))
    table_size = 2**n

    return (table_size, n)

import math

def calculate_pir_config(n: int, bucket_num_option: int) -> tuple[int, int, int, int]:
    if n == 0:
        raise ValueError("N must be greater than 0 to calculate PIR configuration.")

    if bucket_num_option == 0 or (bucket_num_option & (bucket_num_option - 1)) != 0:
        raise ValueError(f"BUCKET_NUM_OPTION ({bucket_num_option}) must be a power of 2.")

    try:
        db_size = 1 << n
    except OverflowError:
        raise OverflowError(f"N ({n}) is too large, 1 << N overflowed.")

    sqrt_db_size = math.sqrt(db_size)
    if not math.isfinite(sqrt_db_size):
        raise ValueError(f"Square root calculation resulted in non-finite value for N={n}")

    sqrt_db_floor = math.floor(sqrt_db_size)
    max_k_float = sqrt_db_floor / n

    if not math.isfinite(max_k_float):
        raise ValueError(f"Max k calculation resulted in non-finite value for N={n}")

    max_k_allowed = math.floor(max_k_float)

    if max_k_allowed == 0:
        if n > sqrt_db_floor:
            print(f"Warning: For N={n}, even 1 bucket violates the condition ({n} > {sqrt_db_floor}). "
                  f"Defaulting to 1 bucket anyway.")
        base_num_buckets = 1
    else:
        # Find the largest power of 2 <= max_k_allowed
        base_num_buckets = 1 << (max_k_allowed.bit_length() - 1)

    # Multiply by bucket_num_option
    num_buckets = base_num_buckets * bucket_num_option
    if num_buckets > db_size:
        max_feasible_option = db_size // base_num_buckets
        valid_options = []
        option = 1
        while option <= max_feasible_option:
            valid_options.append(str(option))
            option *= 2
        raise ValueError(
            f"BUCKET_NUM_OPTION ({bucket_num_option}) results in too many buckets ({num_buckets}). "
            f"Cannot have more buckets than database entries ({db_size}). "
            f"Valid power-of-2 BUCKET_NUM_OPTION values for N={n} are: {', '.join(valid_options)}"
        )

    bucket_size = db_size // num_buckets
    if bucket_size == 0 or (bucket_size & (bucket_size - 1)) != 0:
        raise ValueError(
            f"BUCKET_NUM_OPTION ({bucket_num_option}) results in bucket_size ({bucket_size}) "
            f"that is not a power of 2. This occurs when num_buckets ({num_buckets}) doesn't divide "
            f"db_size ({db_size}) into power-of-2 chunks. Try a different BUCKET_NUM_OPTION value."
        )

    bucket_bits = bucket_size.bit_length() - 1

    return db_size, num_buckets, bucket_size, bucket_bits



# we need at least 256 MB for 2^20 * 256 B entries
print(calculate_required_table_size(256 * 1024 * 1024, 256))  # 2^20 * 256 B entries

# we need at least 3840 MB for 2^17 * 30kB entries
print(calculate_required_table_size(3840 * 1024 * 1024, 30720))  # 2^17 * 30kB entries

print(calculate_required_table_size(1920 * 1024 * 1024, 30720))  # 2^16 * 30kB entries

# we need at least around 1,562.5 MB so 2 GB is also good for 2^14 * 100kB entries
print(calculate_required_table_size(2 * 1024 * 1024 * 1024, 100000))  # 2^14 * 100kB entries
