# Import the necessary modules from cryptography library and other modules for the program to work.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
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

# Define a function to encrypt a plain text file (task1.txt) and generate the encrypted file.
# A key derivation fucntion (PBKDF) is used to generate a strong key from the password,
# salt is used for better security.
# https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
def file_encryption(input_file_path, output_file_path, password):
    # KEY GENERATION
    # generate a random salt.
    salt = os.urandom(16)
    # generate the key using a key derivation function PBKDF.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    # Display the key to user. hexadecimal format.
    print('─' * 10)
    print(f"Generated Key: {binascii.hexlify(key).decode()}")
    print('─' * 10)
    
    # FILE ENCRYPTION
    # A random Initialization Vector (IV) is generated,
    # ALGORITHM: AES, MODE: CBC.
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    # open the plaintext file to be read byte by byte,
    # using mode= rb (read, byte).
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    
    # Padding is used because AES CBC MODE requires it.
    # PKCS7 padding is used to make sure the plaintext is a multiple of the block size.
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # generate the encrypted text as cipher text, final step of encryption.
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Display the encrypted output in hexadecimal format to user
    print(f"Encrypted Output: {binascii.hexlify(ciphertext).decode()}")
    print('─' * 10)

    # create the encrypted file, using mode= wb (write).
    # The salt, IV, and encrypted data are all written to the output file.
    with open(output_file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

# Define a function to decrypt an encrypted file and generate the decrypted file.
def file_decryption(input_file_path, output_file_path, password):
    # Open the encrypted file,
    # extract the salt and the iv,
    # then read the encrypted content.
    with open(input_file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        ciphertext = f.read()

    # generate the key for decryption.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())

    # FILE DECRYPTION
    # set up the decryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # unpad the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    # generate the decrypted text as plain text, final step of decryption
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Display the decrypted output to user
    print("Decrypted Output: ")
    print(f"{plaintext.decode()}")
    print('─' * 10)

    # create the decrypted file, using mode= wb (write).
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)

# Input and output file paths
input_file = os.path.join(INPUT_DIR, "task1.txt")
encrypted_file = os.path.join(OUTPUT_DIR, "encrypted_task1.txt")
decrypted_file = os.path.join(OUTPUT_DIR, "decrypted_task1.txt")

# call encryption function
# student number used for password for the third argument
file_encryption(input_file, encrypted_file, '4006119')

# call decryption function 
# student number used for password for the third argument
file_decryption(encrypted_file, decrypted_file, '4006119')
