###########################################################################
# NOTE: Please install the required libararies to make the code work.
#       These libraries are cv2 and numpy
#           for cv2: pip install opencv-python / pip3 install opencv-python
#           for numpy: pip install numpy / pip3 install numpy
###########################################################################

# Import the necessary modules from cryptography library and other modules for the program to work.
# Import modules for AES encryption
import os
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from os import urandom
# Import modules for steganography 
import math
from os import path
import cv2
import numpy as np

# Define BASE variable for making paths work on all OS.
BASE = os.path.dirname(os.path.abspath(__file__))

# Define subdirectories for input and output
INPUT_DIR = os.path.join(BASE, 'input')
OUTPUT_DIR = os.path.join(BASE, 'output')

# Ensure directories exist
os.makedirs(INPUT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Embed secret in the n least significant bit.
# Lower n make picture less loss but lesser storage capacity.
BITS = 2

HIGH_BITS = 256 - (1 << BITS)
LOW_BITS = (1 << BITS) - 1
BYTES_PER_BYTE = math.ceil(8 / BITS)
FLAG = '%'

# AES encryption
def aes_encryption(plaintext):
    # Generate a random symmetric key for AES (AES-256)
    symmetric_key = urandom(32)  # 256-bit key
    iv = urandom(16)  # Initialization vector
    
    # Cipher setup (AES-CBC with PKCS7 padding)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    encryptor = cipher.encryptor() 
    
    # Pad the plaintext to be a multiple of AES block size (128 bits)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext, symmetric_key, iv

# AES decryption
def aes_decryption(ciphertext, symmetric_key, iv):
    # set up the decryptor
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext and unpad it
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# The embed_message_in_image() and extract_message_from_image() functions below were inspired 
# by Samuel Chan from his YouTube video: https://www.youtube.com/watch?v=ZFGlJGwaN2w 
# and GitHub repository: https://github.com/onlyphantom/steganography/tree/main

# Function to embed the encrypted message into the least significant bits (LSB) of an image
def embed_message_in_image(image_path, secret_data):
    # Load the image using OpenCV
    image = cv2.imread(image_path, cv2.IMREAD_ANYCOLOR)
    original_shape = image.shape
    max_capacity = original_shape[0] * original_shape[1] // BYTES_PER_BYTE  # Maximum bytes to hide

    # Convert the message to binary format for embedding
    binary_secret = ''.join([format(byte, '08b') for byte in secret_data])
    
    # Append the length of the binary message to help with extraction later
    binary_length = format(len(binary_secret), '032b')  # 32 bits for message length
    binary_secret = binary_length + binary_secret

    # Ensure the image has enough space to store the message
    assert len(binary_secret) <= max_capacity * BITS, "Message is too large to fit in the image."

    image_data = np.reshape(image, -1)
    bit_index = 0

    # Loop through the image pixels and embed the binary message in the least significant bits
    for i in range(len(image_data)):
        if bit_index < len(binary_secret):
            # Clear the lowest BITS bits in the pixel and set the LSBs with the secret data bits
            image_data[i] &= HIGH_BITS
            image_data[i] |= int(binary_secret[bit_index:bit_index + BITS], 2)
            bit_index += BITS
        else:
            break

    # Reshape the modified pixel data back to its original shape
    modified_image = np.reshape(image_data, original_shape)

    # Get the original file extension
    filename, _ = path.splitext(os.path.basename(image_path))  # Get only the file name from the path

    # Save the image into png format as jpeg will result in data loss due to its lossy compression
    output_path = os.path.join(OUTPUT_DIR, f"{filename}_stego.png") 
    cv2.imwrite(output_path, modified_image)

    return output_path

# Function to extract the embedded message from the least significant bits of an image
def extract_message_from_image(stego_image_path):
    # Load the stego image with the hidden message
    image = cv2.imread(stego_image_path, cv2.IMREAD_ANYCOLOR)
    image_data = np.reshape(image, -1)

    # Extract the first 32 bits to determine the length of the embedded message
    binary_length = ''
    for i in range(32 // BITS):
        binary_length += format(image_data[i] & LOW_BITS, f'0{BITS}b')

    # Convert the extracted binary length into an integer (number of bits in the message)
    message_length = int(binary_length, 2)

    # Now extract the actual message based on the length obtained
    binary_secret = ''
    for i in range(32 // BITS, (32 + message_length) // BITS):
        binary_secret += format(image_data[i] & LOW_BITS, f'0{BITS}b')

    # Convert the binary secret back to bytes
    byte_secret = bytearray()
    for i in range(0, len(binary_secret), 8):
        byte_secret.append(int(binary_secret[i:i+8], 2))

    return bytes(byte_secret)

# Main function for encryption, embedding, extraction, and decryption
def main():
    # Prompt user for a plaintext message
    print('─' * 10)
    plaintext_message = input("Enter the plaintext message to hide: ").encode('utf-8')
    print('─' * 10)

    # AES Encryption
    print("Encrypting...")
    print("")
    ciphertext, symmetric_key, iv = aes_encryption(plaintext_message)

    # Print key, iv and encrypted message to terminal
    print(f"Symmetric Key: {binascii.hexlify(symmetric_key).decode()}")
    print("")
    print(f"Encrypted Message: {binascii.hexlify(ciphertext).decode()}")
    print('─' * 10)

    # File paths
    input_image_path = os.path.join(INPUT_DIR, "kali_linux_black_image.jpeg")
    output_image_path = os.path.join(OUTPUT_DIR, "kali_linux_black_image_stego.png")

    # Embed the encrypted message in the image
    print(f"Embedding...")
    print("")
    embed_message_in_image(input_image_path, ciphertext)
    print(f"Message Successfully Embedded in {output_image_path}")
    print('─' * 10)


    # # Extract the hidden message from the image
    print("Extracting...")
    print("")
    extracted_message = extract_message_from_image(output_image_path)
    print(f"Extracted Message: {binascii.hexlify(extracted_message).decode()}")
    print('─' * 10)

    # AES Decryption
    print("Decrypting...")
    decrypted_message = aes_decryption(extracted_message, symmetric_key, iv)
    print("")
    print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")
    print('─' * 10)

if __name__ == "__main__":
    main()
