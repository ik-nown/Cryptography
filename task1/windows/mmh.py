import os
import random
import string

# Kích thước của tệp đích (100MB)
target_size = 15 * 1024 * 1024  # 20MB in bytes

# Tên tệp đích
output_file = '6.txt'

# Tạo tệp văn bản ngẫu nhiên
with open(output_file, 'w') as file:
    while os.path.getsize(output_file) < target_size:
        random_text = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation + string.whitespace) for _ in range(1024))  # 1KB of random data
        file.write(random_text)

print(f"Created a random text file of size {os.path.getsize(output_file) / (1024 * 1024):.2f} MB.")
