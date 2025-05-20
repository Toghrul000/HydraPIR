import csv
import os
import string
import random



def generate_fixed_size_csv(filename, num_rows):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['key', 'value'])  # CSV header

        for i in range(num_rows):
            key = f'key{i}'
            key_len = len(key.encode('utf-8'))
            total_len = 252
            comma_len = 1
            value_len = total_len - key_len - comma_len

            if value_len <= 0:
                raise ValueError(f"Key '{key}' is too long to fit in 256 bytes with a value.")

            # Generate a fixed-length ASCII value
            value = ''.join(random.choices(string.ascii_letters + string.digits, k=value_len))
            assert len((key + ',' + value).encode('utf-8')) == total_len
            writer.writerow([key, value])


# Example usage
generate_fixed_size_csv('dummy_data.csv', 1000000)  
