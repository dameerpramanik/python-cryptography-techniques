# Import the necessary modules from cryptography library and other modules for the program to work.
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import time

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
def rsa_keys_generation(key_size):
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    # Derive the public key from the private key
    public_key = private_key.public_key()

    # Save private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_path = os.path.join(KEYS_DIR, f"private_key_{key_size}.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key_pem)

    # Save public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_path = os.path.join(KEYS_DIR, f"public_key_{key_size}.pem")
    with open(public_key_path, "wb") as f:
        f.write(public_key_pem)

    return private_key, public_key

# Define a function to encrypt a file using RSA and public key
def rsa_file_encryption(file_path, public_key, output_path):
    # Read the plaintext data from the file
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Encrypt the data using OAEP padding
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the encrypted data to the output file
    with open(output_path, "wb") as file:
        file.write(ciphertext)

# Define a function to decrypt an encrypted file using RSA and private key
def rsa_file_decryption(encrypted_file_path, private_key, output_path):
    # Read the encrypted data from the file
    with open(encrypted_file_path, "rb") as file:
        ciphertext = file.read()

    # Decrypt the data using OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Write the decrypted data to the output file
    with open(output_path, "wb") as file:
        file.write(plaintext)

# RSA DIGITAL SIGNATURE
# Define a function to sign the data using RSA private key
def data_signature(data, private_key):
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify the signature
def verify_signature(data, signature, public_key):
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False
    
# Define a funciton to measure encryption and decryption time for a given key size.
def measure_performance(key_size):
    # Generate keys
    private_key, public_key = rsa_keys_generation(key_size)

    # Input and output file paths
    input_file = os.path.join(INPUT_DIR, "task3.txt")
    encrypted_file = os.path.join(OUTPUT_DIR, f"encrypted_task3_{key_size}.txt")
    decrypted_file = os.path.join(OUTPUT_DIR, f"decrypted_task3_{key_size}.txt")

    # Encrypt the file and measure the time
    initial_time = time.time()
    rsa_file_encryption(input_file, public_key, encrypted_file)
    encryption_time = time.time() - initial_time
    print(f"Encryption time with {key_size}-bit key: {encryption_time:.6f} seconds")

    # Decrypt the file and measure time
    initial_time = time.time()
    rsa_file_decryption(encrypted_file, private_key, decrypted_file)
    decryption_time = time.time() - initial_time
    print(f"Decryption time with {key_size}-bit key: {decryption_time:.6f} seconds")

    # # sign the original data with the private key
    # signature = data_signature(original_data, private_key)
    # print(f"Signature (hex) with {key_size}-bit key: {signature.hex()}")

    # # Verify the signature with the public key
    # is_valid = verify_signature(original_data, signature, public_key)
    # print(f"Signature valid with {key_size}-bit key: {is_valid}")

if __name__ == "__main__":
    # Measure performance for 1024-bit and 2048-bit keys
    # This also shows that parts i, ii, iii, iv and v
    # have been implemented successfully as it
    #   generates keys (1024-bit), stores in keys sub-directory
    #   encrypts task3.txt, RSA with padding
    #   includes support for RSA digital signatures with functions data_signature() and verify_signature()
    #   decrypts the ciphertext, saves it in a file
    #   finally, shows the time comparisons between encryption and decryption using 1024-bit key and 2048-bit key
    print('─' * 10)
    measure_performance(1024)
    print('─' * 10)
    measure_performance(2048)
    print('─' * 10)
