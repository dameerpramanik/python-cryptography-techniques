# Application of Cryptography Techniques in Python

This project demonstrates the practical application of various cryptography techniques using Python. The techniques covered include AES-CBC encryption, RSA encryption, Hybrid encryption, Manual RSA implementation, and Steganography.

## Key Skills Demonstrated

1. **AES-CBC Encryption**: Implementing AES encryption in CBC mode with PKCS7 padding.
2. **RSA Encryption**: Generating RSA keys, encrypting and decrypting messages using RSA.
3. **Hybrid Encryption**: Combining RSA and AES encryption to leverage the strengths of both.
4. **Manual RSA Implementation**: Manually implementing RSA encryption and decryption without using high-level libraries.
5. **Steganography**: Hiding encrypted messages within images using the least significant bit (LSB) technique.

## Project Structure

- `task1-aes-cbc.py`: Demonstrates AES-CBC encryption and decryption.
- `task2-aes-cbc.py`: Decrypts a given AES-CBC encrypted message.
- `task3-rsa.py`: Implements RSA encryption, decryption, and digital signatures.
- `task4-hybrid.py`: Combines RSA and AES for hybrid encryption.
- `task5-rsa-manual.py`: Manually implements RSA encryption and decryption.
- `task6-hide-and-seek.py`: Hides encrypted messages within images using steganography.
- `input/`: Contains input files for the tasks.
- `keys/`: Stores generated keys.
- `output/`: Stores output files, including encrypted and decrypted messages.

## How to Run

1. **Install Required Libraries**:
   Ensure you have the required libraries installed. You can install them using pip:
   ```sh
   pip install cryptography opencv-python numpy
   ```

2. **Run Each File Independently**:
   Each task can be run independently. The results will be outputted either in the terminal or in the `output` directory. Keys will be stored in the `keys` directory, and input files are located in the `input` directory.

   For example, to run `task1-aes-cbc.py`, use:
   ```sh
   python task1-aes-cbc.py
   ```

   Similarly, you can run other tasks:
   ```sh
   python task2-aes-cbc.py
   python task3-rsa.py
   python task4-hybrid.py
   python task5-rsa-manual.py
   python task6-hide-and-seek.py
   ```

3. **Check Output**:
   - Encrypted and decrypted messages will be stored in the `output` directory.
   - Generated keys will be stored in the `keys` directory.
   - Input files are located in the `input` directory.

## Notes

- Ensure that the input files required for each task are present in the `input` directory.
- The `task6-hide-and-seek.py` script requires an image file (`kali_linux_black_image.jpeg`) in the `input` directory for steganography.

By following these instructions, you can explore and understand the implementation of various cryptography techniques in Python.

# Acknowledgements
This project was originally developed as part of an RMIT University assignment. Some code structures were inspired by provided course materials.

# Author
* Dameer Pramanik