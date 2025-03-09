# Import the necessary modules from cryptography library and other modules for the program to work.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import os.path
import binascii

# Define BASE variable for making paths working on all OS.
BASE = os.path.dirname(os.path.abspath(__file__))

# Define subdirectories for keys, input, and output
INPUT_DIR = os.path.join(BASE, 'input')
OUTPUT_DIR = os.path.join(BASE, 'output')

# Ensure directories exist
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Define a function that takes in hex-encoded ciphertext and key to decrypt that ciphertext and generate the decrypted file.
def decrypt_aes_cbc(hex_ciphertext, hex_key, output_file_path):
    # Convert the hex-encoded ciphertext from hexadecimal to binary
    ciphertext = binascii.unhexlify(hex_ciphertext)
    # Convert the hex-encoded key from hexadecimal to binary
    key = binascii.unhexlify(hex_key)

    # Extract the Intialisation Vector (IV) from the ciphertext
    # first 16 bytes.
    iv = ciphertext[:16]
    real_ciphertext = ciphertext[16:]

    # set up the decryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # perform decryption
    padded_plaintext = decryptor.update(real_ciphertext) + decryptor.finalize()

    # Unpad the plaintext (PKCS7 padding)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    # generate the decrypted text as plain text, final step of decryption
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Display the decrypted output to the user
    print('─' * 10)
    print(f"Decrypted Output: {plaintext.decode()}")
    print('─' * 10)

    # create the decrypted file, using mode= wb (write).
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    
# Hardcoded AES key and ciphertext (both are hex-encoded)
hex_key = '140b41b22a29beb4061bda66b6747e14'
hex_ciphertext = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'

# call decryption function
# save the decrypted file in output sub-directory as decrypted_task2.txt
decrypted_file = os.path.join(OUTPUT_DIR, "decrypted_task2.txt")
decrypt_aes_cbc(hex_ciphertext, hex_key, decrypted_file)    