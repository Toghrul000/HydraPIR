import csv
import os
import string
import random
import math

def generate_fixed_size_csv(filename, n, total_len):
    """
    Generates a CSV file with a number of rows equal to approximately 90% of 2^n,
    with each row (excluding newline) having a fixed total byte length.

    Args:
        filename: The name of the CSV file to generate.
        n: The exponent for the base 2 to calculate the approximate number of rows.
        total_len: The target total byte length for each row (key,value), excluding newline.
                   The actual used length will be total_len - 4.
    """
    # Adjust total_len since encoding adds 4 bytes
    actual_row_len = total_len - 4

    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['key', 'value'])  # CSV header

        # Calculate the number of rows based on n
        num_rows_float = (2**n) * 0.9
        num_rows = round(num_rows_float)

        for i in range(num_rows):
            key = f'key{i}'
            key_len = len(key.encode('utf-8'))

            comma_len = 1
            value_len = actual_row_len - key_len - comma_len

            if value_len < 0:
                 # This might occur if a key becomes excessively long.
                print(f"Warning: Skipping row {i} due to key length exceeding available space.", file=math.stderr)
                continue 

            # Generate a fixed-length ASCII value
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=max(0, value_len))) # Ensure non-negative k
            
            assert len((key + ',' + value).encode('utf-8')) == actual_row_len

            writer.writerow([key, value])

# Example usage
# Generates a CSV with approximately 90% of 2^20 rows, with each row being 252 bytes (256 - 4)
generate_fixed_size_csv('dummy_data_n_20.csv', 20, 256)
# Generates a CSV with approximately 90% of 2^17 rows, with each row being (30000 - 4) bytes
generate_fixed_size_csv('dummy_data_n_17.csv', 17, 30000)
# Generates a CSV with approximately 90% of 2^14 rows, with each row being (100000 - 4) bytes
generate_fixed_size_csv('dummy_data_n_14.csv', 14, 100000)
