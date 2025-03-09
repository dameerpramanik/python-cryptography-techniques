####################################################################################################
# In this code I turn the below rsa method into code.
####################################################################################################
# Choose random primes p and q
# Compute n = p * q 
# Compute Totient r = (p - 1) * (q - 1) 
# Choose e such that 1 < e < r and e and r are coprime ie gcd (e,r) =1
# Compute a value for d = e ^-1 mod (r)

# Public key is (e, n) 
# Private key is (d) 

# Plaintext m
# Encryption = 

# Ciphertext c = m^e mod(n)

# Decryption = c^d mod (n)
####################################################################################################

# Import the necessary modules for the program to work.
# The random module is used to generate large random numbers, while the gcd function 
# from math ensures that two numbers are coprime (gcd(e, r) == 1).
import random
from math import gcd
import os
import os.path

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

# Padding Length
# Padding size of 10 is added to ensure the message is secure and meets the 
# size requirement for encryption. Padding is crucial for security in RSA.
PADDING_SIZE = 10

# RSA PRIVATE & PUBLIC KEY GENERATION
# Step 1: Define function to generate large random prime numbers p and q
# RSA encryption requires two large prime numbers, p and q. These primes 
# will be used to calculate the modulus n, which is a core part of the RSA keys.
def is_prime_num(num):
    # Check if a number is prime by testing divisibility.
    # A prime number is a number greater than 1 that has no divisors other than 1 and itself.
    if num < 2:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

def random_large_prime_num():
    # Generate a large prime number with at least 6 digits.
    # RSA works best with large prime numbers to ensure security.
    # This function keeps generating random numbers until it finds a prime.
    while True:
        # Generates random 6 digits number or higher up to 10 digits
        possible_prime = random.randint(100000, 9999999999) 
        if is_prime_num(possible_prime):
            return possible_prime

# Step 2: Compute n = p * q, where p and q are large primes
# n is the modulus used for both the public and private keys. The product of
# two primes ensures that factoring n becomes the basis for RSA's security.
p = random_large_prime_num()
q = random_large_prime_num()
n = p * q

# Step 3: Compute the Totient r = (p-1) * (q-1)
r = (p - 1) * (q - 1)

# Step 4: Choose e such that 1 < e < r and e and r are coprime ie gcd (e,r) =1
# e is the public exponent. It must be coprime with r so that a valid modular
# inverse (d) can be calculated later. This ensures that the encryption and decryption processes
# can work properly.
def find_coprime(r):
    # This function finds an integer e such that e is coprime with r (i.e., gcd(e, r) = 1).
    # The coprime condition ensures that e and r share no common factors, which is required for RSA encryption.
    e = random.randint(2, r -1) # Start by selecting a random number between 2 and r-1.
    while gcd(e, r) != 1: # If e is not coprime with r, select a new random number.
        e = random.randint(2, r - 1)
    return e  # Return e, which satisfies gcd(e, r) = 1.

e = find_coprime(r)

# The following code for modular inverse was inspired by ChatGPT (accessed on 30/09/2024)
# ChatGPT was used to help understand how to implement the extended Euclidean algorithm 
# to compute the modular inverse. No shareable link is available for this specific response.
# The prompt used was: "Explain how to compute modular inverse using extended Euclidean algorithm in Python."
# Step 5: Compute d such that d = e ^-1 mod (r)
def mod_inverse(e, r):
    # This function computes the modular inverse of e modulo r using the extended Euclidean algorithm.
    # The modular inverse d ensures that (m^e)^d mod n = m, completing the RSA decryption process.
    # The extended Euclidean algorithm helps find d such that (e * d) ≡ 1 (mod r).
    def extended_gcd(a, b):
        # Helper function to return gcd and coefficients of Bezout's identity (gcd = a*x + b*y).
        if b == 0:
            return a, 1, 0  # Base case: gcd is a, coefficients are 1 and 0.
        gcd, x1, y1 = extended_gcd(b, a % b)  # Recursively apply the Euclidean algorithm.
        x = y1  # Update x and y based on recursive results.
        y = x1 - (a // b) * y1
        return gcd, x, y
    
    # Compute the modular inverse of e mod r using the results from extended_gcd.
    gcd_value, x, y = extended_gcd(e, r)
    return x % r  # Return x as the modular inverse

d = mod_inverse(e, r) 

# Public key is (e, n), private key is (d)

# Step 6: Fase modular exponentiation (Square-and-Multiply algorithm)
def modular_exponentiation(base, exp, mod):
    """Perform fast modular exponentiation."""
    # This function implements the square-and-multiply algorithm, which is an efficient way to compute large powers modulo a number.
    # RSA encryption requires the computation of m^e mod n, and decryption requires c^d mod n. Direct computation would be slow, but 
    # square-and-multiply optimizes this process.
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:  # If exp is odd, multiply base with result
            result = (result * base) % mod
        exp = exp // 2  # Divide the exponent by 2
        base = (base * base) % mod  # Square the base
    return result

def apply_padding(message, n):
    """Apply simple padding to the message."""
    # Convert message to bytes and add random padding (using random integers for demo)
    padding = random.randint(10**(PADDING_SIZE-1), 10**PADDING_SIZE - 1)
    padded_message = str(padding) + str(message)  # Random padding + message
    padded_int = int(padded_message)  # Convert the padded message to an integer
    # Ensure the padded message is smaller than n
    if padded_int >= n:
        raise ValueError("Padded message is too large for encryption.")
    return padded_int

# Remove Padding
# After decryption, we need to remove the padding to recover the original message.
# The padding is stripped off by removing the first few digits, which represent the padding.
def remove_padding(padded_message):
    """Remove padding from the decrypted message."""
    # Strip off the first PADDING_SIZE digits (padding)
    padded_str = str(padded_message)
    return int(padded_str[PADDING_SIZE:])  # Extract original message

# RSA ENCRYPTION AND DECRYPTION
# Step 7: Define encrypt and decrypt functions using RSA
def encrypt_message(input_file, output_file, e, n):
    # Read the plaintext data from the file
    with open(input_file, "r") as file:
        m = file.read()

    # Encrypt the message (m) using RSA Public key (e, n)
    padded_message = apply_padding(m, n) # Apply padding before encryption
    print('─' * 10)
    print(f"Padded message: {padded_message}")
    encrypted_message = modular_exponentiation(padded_message, e, n)
    print('─' * 10)
    print(f"Encrypted padded message: {encrypted_message}")
    print('─' * 10)

    # Write the encrypted data to the output file
    with open(output_file, "w") as file:
        file.write(str(encrypted_message))

    return encrypted_message

def decrypt_message(input_file, output_file, d, n):
    # Read the encrypted data from the file
    with open(input_file, "r") as file:
        c = int(file.read())
    
    # Decrypt the encrypted message (c) using RSA Private key (d)
    padded_message = modular_exponentiation(c, d, n)
    print(f"Decrypted padded message: {padded_message}")
    print('─' * 10)
    decrypted_message = remove_padding(padded_message) # Remove padding after decryption
    print(f"Decrypted message: {decrypted_message}")
    print('─' * 10)

    # Write the decrypted data to the output file
    with open(output_file, "w") as file:
        file.write(str(decrypted_message))

    return decrypted_message

# Input and output file paths
input_file = os.path.join(INPUT_DIR, "task5.txt")
encrypted_file = os.path.join(OUTPUT_DIR, f"encrypted_task5.txt")
decrypted_file = os.path.join(OUTPUT_DIR, f"decrypted_task5.txt")

# Encrypt the message
encrypted_message = encrypt_message(input_file, encrypted_file, e, n)

# Decrypt the message
decrypted_message = decrypt_message(encrypted_file, decrypted_file, d, n)