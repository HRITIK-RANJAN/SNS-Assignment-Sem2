import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. Manual PKCS#7 Padding (STRICT REQUIREMENT)

def pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Applies PKCS#7 padding to the data.
    The value of each padding byte equals the number of padding bytes added.
    """
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Removes and validates PKCS#7 padding.
    """
    if not data:
        raise ValueError("Data is empty.")
    
    padding_len = data[-1]
    
    # Validate padding length
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid padding length.")
    
    # Validate all padding bytes are identical
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid padding bytes.")
        
    return data[:-padding_len]

# 2. AES-128-CBC Encryption/Decryption

def encrypt_aes_128_cbc(key: bytes, plaintext: bytes) -> tuple:
    """
    Encrypts data using AES-128-CBC.
    Returns (iv, ciphertext).
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes.")
        
    iv = os.urandom(16) # Generate random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

def decrypt_aes_128_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts data using AES-128-CBC.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes.")
        
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# 3. HMAC-SHA256

def compute_hmac(key: bytes, message: bytes) -> bytes:
    """
    Computes HMAC-SHA256 over the message.
    """
    return hmac.new(key, message, hashlib.sha256).digest()