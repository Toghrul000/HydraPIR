#!/usr/bin/env python3
import math
import argparse
from typing import Tuple

def calculate_required_table_size(
    total_storage_bytes: int, entry_size_bytes: int
) -> Tuple[int, int]:
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

    # Calculate the maximum number of entries that *can* fit
    max_entries_possible = total_storage_bytes // entry_size_bytes

    # If no entries can fit, the smallest valid power of 2 size is 1 (2^0)
    if max_entries_possible == 0:
        return (1, 0)

    # Find the largest power of 2 that is less than or equal to max_entries_possible
    n = int(math.floor(math.log2(max_entries_possible)))
    table_size = 2**n

    return (table_size, n)

def calculate_required_storage(n: int, entry_size_bytes: int) -> int:
    """
    Calculates the required storage size in MB for a table of size 2^n with given entry size.
    
    Args:
        n: The power of 2 for table size (table_size = 2^n)
        entry_size_bytes: Size of each entry in bytes
        
    Returns:
        Required storage size in MB (rounded up to nearest integer)
    """
    # Calculate total bytes needed
    total_bytes = (2 ** n) * entry_size_bytes
    
    # Convert to MB and round up
    total_mb = math.ceil(total_bytes / (1024 * 1024))
    
    return total_mb

def validate_storage(n: int, entry_size_bytes: int, storage_mb: int) -> bool:
    """
    Validates if the given storage size is sufficient for the table configuration.
    
    Args:
        n: The power of 2 for table size
        entry_size_bytes: Size of each entry in bytes
        storage_mb: Available storage in MB
        
    Returns:
        True if storage is sufficient, False otherwise
    """
    # Convert storage_mb to bytes
    storage_bytes = storage_mb * 1024 * 1024
    
    # Calculate what table size we can actually fit
    actual_table_size, actual_n = calculate_required_table_size(storage_bytes, entry_size_bytes)
    
    # Check if we can fit the desired table size
    return actual_n >= n

def main():
    parser = argparse.ArgumentParser(description='Calculate required storage size for KPIR configuration')
    parser.add_argument('n', type=int, help='Power of 2 for table size (table_size = 2^n)')
    parser.add_argument('entry_size', type=int, help='Size of each entry in bytes')
    
    args = parser.parse_args()
    
    # Calculate required storage
    required_mb = calculate_required_storage(args.n, args.entry_size)
    
    # Validate the calculation
    is_valid = validate_storage(args.n, args.entry_size, required_mb)
    
    print(f"\nConfiguration:")
    print(f"Table size: 2^{args.n} = {2**args.n} entries")
    print(f"Entry size: {args.entry_size} bytes")
    print(f"\nRequired storage: {required_mb} MB")
    
    if is_valid:
        print("\nValidation: ✓ Storage size is sufficient")
    else:
        print("\nValidation: ✗ Storage size is insufficient!")
        print("Please increase the storage size.")

if __name__ == "__main__":
    main() 