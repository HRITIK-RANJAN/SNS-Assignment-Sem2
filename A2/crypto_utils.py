import random
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import struct

def modular_exponentiation(base, exponent, modulus):
  
    result = 1
    base = base % modulus
    
    while exponent > 0:
        # If exponent is odd, multiply base with result
        if exponent % 2 == 1:
            result = (result * base) % modulus
        
        # exponent must be even now
        exponent = exponent >> 1  # Divide by 2
        base = (base * base) % modulus
    
    return result


def extended_euclidean(a, b):
    # Iterative version to avoid stack overflow with large numbers
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    
    return old_r, old_s, old_t  # gcd, x, y


def modular_inverse(a, m):

    gcd, x, _ = extended_euclidean(a, m)
    
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for a={a}, m={m}")
    
    return (x % m + m) % m


def gcd(a, b):

    while b:
        a, b = b, a % b
    return a


# Prime Number Generation

def is_prime_miller_rabin(n, k=40):
    # Handle small cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        # Pick random witness a in range [2, n-2]
        a = random.randint(2, n - 2)
        
        x = modular_exponentiation(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        composite = True
        for _ in range(r - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                composite = False
                break
        
        if composite:
            return False
    
    return True


def generate_large_prime(bit_length):
    # Generate random odd number in range
    while True:
        # Generate random number with correct bit length
        p = random.getrandbits(bit_length)
        
        # Set highest bit to ensure correct bit length
        p |= (1 << (bit_length - 1))
        
        # Make it odd
        p |= 1
        
        # Test for primality
        if is_prime_miller_rabin(p, k=40):
            return p


def find_generator(p):

    p_minus_1 = p - 1
    
    # Most common prime factors of p-1 for safe primes
    # For primes of form p = 2q+1 (Sophie Germain primes), p-1 = 2*q
    # So we need to check: g^2 != 1 mod p and g^q != 1 mod p
    
    # For simplicity and speed: check small candidates
    # Statistically, generators are very common (density ~ phi(p-1)/(p-1))
    # For most primes, 2, 3, 5 will include a generator
    
    candidates = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    
    for g in candidates:
        if g >= p:
            continue
        # Quick test: check if g^2 != 1 (mod p)
        # This is necessary for g to be a generator for most primes
        if modular_exponentiation(g, 2, p) != 1:
            if modular_exponentiation(g, p_minus_1 // 2, p) != 1:
                return g
    
    # If small primes don't work, do exhaustive search up to 100
    # (should rarely reach here)
    for g in range(2, min(p, 100)):
        if modular_exponentiation(g, 2, p) != 1:
            if modular_exponentiation(g, p_minus_1 // 2, p) != 1:
                return g
    
    # Fallback: return 2 (highly probable generator for cryptographic primes)
    return 2


# ============================================================================
#  ElGamal Key Generation
# ============================================================================

class ElGamalKey:
    """Container for ElGamal public/private keys."""
    
    def __init__(self, p, g, x=None, y=None, sl=None):
      
        self.p = p
        self.g = g
        self.x = x  # Private key
        self.y = y  # Public key
        self.sl = sl or p.bit_length()


def generate_elgamal_keypair(p, g):
  
    # Generate random private key x in [1, p-2]
    x = random.randint(1, p - 2)
    
    # Compute public key y = g^x mod p
    y = modular_exponentiation(g, x, p)
    
    return ElGamalKey(p, g, x=x, y=y)


# ============================================================================
#  ElGamal Encryption/Decryption
# ============================================================================

def elgamal_encrypt(message, public_key):
  
    p = public_key.p
    g = public_key.g
    y = public_key.y
    
    # Ensure message is in valid range
    message = message % p
    
    # Generate random k in [1, p-2]
    k = random.randint(1, p - 2)
    
    # Compute c1 = g^k mod p
    c1 = modular_exponentiation(g, k, p)
    
    # Compute y^k mod p
    y_k = modular_exponentiation(y, k, p)
    
    # Compute c2 = (m * y^k) mod p
    c2 = (message * y_k) % p
    
    return (c1, c2)


def elgamal_decrypt(ciphertext, private_key):
   
    p = private_key.p
    x = private_key.x
    
    c1, c2 = ciphertext
    
    # Compute s = c1^x mod p
    s = modular_exponentiation(c1, x, p)
    
    # Compute s_inv = s^(-1) mod p
    s_inv = modular_inverse(s, p)
    
    # Compute m = (c2 * s_inv) mod p
    m = (c2 * s_inv) % p
    
    return m


# ============================================================================
#  ElGamal Digital Signatures
# ============================================================================

def elgamal_sign(message_hash, private_key):
    p = private_key.p
    g = private_key.g
    x = private_key.x
    
    message_hash = message_hash % (p - 1)
    
    # Generate random k such that gcd(k, p-1) = 1
    while True:
        k = random.randint(1, p - 2)
        if gcd(k, p - 1) == 1:
            break
    
    # Compute r = g^k mod p
    r = modular_exponentiation(g, k, p)
    
    # Compute k_inv = k^(-1) mod (p-1)
    k_inv = modular_inverse(k, p - 1)
    
    # Compute s = (H(m) - x*r) * k_inv mod (p-1)
    s = ((message_hash - x * r) * k_inv) % (p - 1)
    
    return (r, s)


def elgamal_verify(message_hash, signature, public_key):
    p = public_key.p
    g = public_key.g
    y = public_key.y
    
    r, s = signature
    
    message_hash = message_hash % (p - 1)
    
    # Compute left side: g^H(m) mod p
    left = modular_exponentiation(g, message_hash, p)
    
    # Compute right side: (y^r * r^s) mod p
    y_r = modular_exponentiation(y, r, p)
    r_s = modular_exponentiation(r, s, p)
    right = (y_r * r_s) % p
    
    return left == right


# ============================================================================
#   Hash and MAC Functions
# ============================================================================

def hash_sha256(data):
    """
    SHA-256 hash function.
    
    Args:
        data: bytes or string to hash
    
    Returns:
        bytes (32-byte hash)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def hash_sha256_int(data):
    """Hash data and return as integer."""
    return int.from_bytes(hash_sha256(data), byteorder='big')


def hmac_sha256(key, data):
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hmac.new(key, data, hashlib.sha256).digest()


# ============================================================================
#  AES-256 CBC Mode Encryption/Decryption
# ============================================================================

def aes_encrypt(key, plaintext):

    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Ensure key is 32 bytes
    if len(key) != 32:
        key = hash_sha256(key)
    
    # Generate random 16-byte IV
    iv = os.urandom(16)
    
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad plaintext to block size
    padded_plaintext = pad(plaintext, AES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return iv, ciphertext


def aes_decrypt(key, iv, ciphertext):

    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Ensure key is 32 bytes
    if len(key) != 32:
        key = hash_sha256(key)
    
    # Create AES cipher with same IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt
    padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad
    plaintext = unpad(padded_plaintext, AES.block_size)
    
    return plaintext


# ============================================================================
#  Message Encoding/Decoding
# ============================================================================

def bytes_to_int(data):
    """Convert bytes to integer for ElGamal encryption."""
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(n, length=None):
    if length is None:
        length = (n.bit_length() + 7) // 8
        if length == 0:
            length = 1
    return n.to_bytes(length, byteorder='big')


# Protocol utility functions
def int_to_bytes_variable(n):
    """Convert integer to bytes with length prefix."""
    b = int_to_bytes(n)
    length = len(b).to_bytes(4, byteorder='big')
    return length + b


def bytes_from_int_variable(data, offset=0):
    """Decode integer with length prefix from bytes."""
    length = int.from_bytes(data[offset:offset+4], byteorder='big')
    value = int.from_bytes(data[offset+4:offset+4+length], byteorder='big')
    return value, offset + 4 + length
