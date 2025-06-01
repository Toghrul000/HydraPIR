import csv
import os
import string
import random
import argparse
import sys

def generate_fixed_size_csv(filename, n, total_len):
    """
    Generates a CSV file with a number of rows equal to approximately 90% of 2^n,
    with each row (excluding newline) having a fixed total byte length.

    Args:
        filename: The name of the CSV file to generate.
        n: The exponent for the base 2 to calculate the approximate number of rows.
        total_len: The target total byte length for each row (key,value), excluding newline.
                   The actual used length will be total_len - 16.
    """
    actual_row_len = total_len - 16 

    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['key', 'value'])  # CSV header

        num_rows = round((2 ** n) * 0.9)

        for i in range(num_rows):
            key = f'key{i}'
            key_len = len(key.encode('utf-8'))
            comma_len = 1
            value_len = actual_row_len - key_len - comma_len

            if value_len < 0:
                print(f"Warning: Skipping row {i} due to key length exceeding available space.", file=sys.stderr)
                continue

            value = ''.join(random.choices(string.ascii_letters + string.digits, k=max(0, value_len)))
            assert len((key + ',' + value).encode('utf-8')) == actual_row_len

            writer.writerow([key, value])

def main():
    parser = argparse.ArgumentParser(description="Generate a fixed-size CSV file with key-value pairs.")
    parser.add_argument("filename", help="Name of the output CSV file")
    parser.add_argument("n", type=int, help="Power of 2 for number of rows (approx 90%% of 2^n rows)")
    parser.add_argument("total_len", type=int, help="Total target byte size for each row (including key,value and comma, minus 16 overhead)")

    args = parser.parse_args()
    generate_fixed_size_csv(args.filename, args.n, args.total_len)

if __name__ == "__main__":
    main()


# # Example usage
# # Generates a CSV with approximately 90% of 2^20 rows, with each row being 252 bytes (256 - 16)
# generate_fixed_size_csv('dummy_data_n_20.csv', 20, 256)
# # Generates a CSV with approximately 90% of 2^17 rows, with each row being (30720 - 16) bytes
# generate_fixed_size_csv('dummy_data_n_17.csv', 17, 30720)
# # Generates a CSV with approximately 90% of 2^14 rows, with each row being (100000 - 16) bytes
# generate_fixed_size_csv('dummy_data_n_14.csv', 14, 102400)
