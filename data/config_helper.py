import math

def calculate_required_table_size(total_storage_bytes: int, entry_size_bytes: int) -> tuple[int, int]:
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
        print(f"Warning: calculate_required_table_size called with entry_size_bytes {entry_size_bytes} not multiple of 8. Result might be suboptimal.", file=math.stderr)
        # Proceed anyway, but the user should align ENTRY_SIZE in main

    # Calculate the maximum number of entries that *can* fit
    max_entries_possible = total_storage_bytes // entry_size_bytes

    # If no entries can fit, the smallest valid power of 2 size is 1 (2^0)
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




# we need at least 256 MB for 2^20 * 256 B entries   
print(calculate_required_table_size(256*1024*1024, 256)) # 2^20 * 256 B entries

# we need at least 3840 MB for 2^17 * 30kB entries
print(calculate_required_table_size(3840*1024*1024, 30720)) # 2^17 * 30kB entries

# we need at least around 1,562.5 MB so 2 GB is also good for 2^14 * 100kB entries  
print(calculate_required_table_size(2 * 1024 * 1024 * 1024, 100000)) # 2^14 * 100kB entries  



