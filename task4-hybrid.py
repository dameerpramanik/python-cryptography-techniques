# Import the necessary modules from cryptography library and other modules for the program to work.
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from os import urandom
import os
import os.path
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding

# Define BASE variable for making paths working on all OS.
BASE = os.path.dirname(os.path.abspath(__file__))

# Define subdirectories for keys, input, and output
KEYS_DIR = os.path.join(BASE, 'keys')
INPUT_DIR = os.path.join(BASE, 'input')
OUTPUT_DIR = os.path.join(BASE, 'output')

# Ensure directories exist
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Define a function to Generate and Save RSA keys
def rsa_keys_generation():
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Derive the public key from the private key
    public_key = private_key.public_key()

    # Save private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_path = os.path.join(KEYS_DIR, f"private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key_pem)

    # Save public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_path = os.path.join(KEYS_DIR, f"public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(public_key_pem)
    
    # Display the RSA private key to user. hexadecimal format.
    print('─' * 10)
    print("RSA Private Key: ")
    print(private_key_pem)
    print('─' * 10)

    # Display the RSA public key to user. hexadecimal format.
    print("RSA Public Key: ") 
    print(public_key_pem)
    print('─' * 10)

    return private_key, public_key

def file_encryption(input_file_path, output_file_path, public_key):
    # Generate a random symmetric key for AES
    symmetric_key = urandom(32)  # AES-256

    # Display the key to user. hexadecimal format.
    print(f"Symmetric Key: {binascii.hexlify(symmetric_key).decode()}")
    print('─' * 10)

    # FILE ENCRYPTION AES
    # A random Initialization Vector (IV) is generated,
    # ALGORITHM: AES, MODE: CBC.
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
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
    # The IV, and encrypted data are all written to the output file.
    with open(output_file_path, 'wb') as f:
        f.write(iv + ciphertext)
    
    # RSA
    # Encrypt the symmetric key with RSA
    encrypted_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Display the encrypted output in hexadecimal format to user
    print(f"Encrypted Symmetric Key: {binascii.hexlify(encrypted_key).decode()}")
    print('─' * 10)

    return encrypted_key

def file_decryption(input_file_path, output_file_path, encrypted_key, private_key):
    # Decrypt the symmetric key
    symmetric_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Display the encrypted output in hexadecimal format to user
    print(f"Decrypted Symmetric Key: {binascii.hexlify(symmetric_key).decode()}")
    print('─' * 10)

    # Open the encrypted file,
    # extract the iv,
    # then read the encrypted content.
    with open(input_file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    # FILE DECRYPTION
    # set up the decryptor
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
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

# ENCRYPT AND DECRYPT THE FILE (task1.txt) USING HYBRID ENCRYPTION
# Generate RSA keys
private_key, public_key = rsa_keys_generation()

# Input and output file paths
input_file = os.path.join(INPUT_DIR, "task1.txt")
encrypted_file = os.path.join(OUTPUT_DIR, "encrypted_task4.txt")
decrypted_file = os.path.join(OUTPUT_DIR, "decrypted_task4.txt")

# Encrypt the file using AES and encrypt the symmetric key used using RSA public key
encrypted_key = file_encryption(input_file, encrypted_file, public_key)

# Decrypt the file by decrypting the symmetric key using RSA private key then using
# the decrypted symmetric key to decrypt the encrypted file
file_decryption(encrypted_file, decrypted_file, encrypted_key, private_key)