"""
Secure UAV Command-and-Control System
Cryptographic Utilities Module

Implements manual ElGamal encryption, signatures, and supporting functions.
No high-level cryptographic libraries are used for core algorithms.
"""

import random
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import struct


# ============================================================================
# PHASE 1.1: Helper Mathematical Functions
# ============================================================================

def modular_exponentiation(base, exponent, modulus):
    """
    Compute (base^exponent) % modulus efficiently using binary method.
    
    Algorithm: Square-and-multiply method
    Time Complexity: O(log exponent)
    
    Args:
        base: The base
        exponent: The exponent
        modulus: The modulus
    
    Returns:
        (base^exponent) % modulus
    
    Example: 
        modular_exponentiation(3, 5, 7) = 5
    """
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
    """
    Extended Euclidean Algorithm.
    
    Returns (gcd, x, y) such that ax + by = gcd(a,b)
    
    Used for computing modular inverse.
    
    Args:
        a: First number
        b: Second number
    
    Returns:
        Tuple (gcd, x, y) where gcd = gcd(a,b) and ax + by = gcd
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_euclidean(b % a, a)
    
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


def modular_inverse(a, m):
    """
    Compute modular multiplicative inverse of a modulo m.
    
    Returns x such that (a * x) % m == 1
    
    Args:
        a: The number to find inverse of
        m: The modulus
    
    Returns:
        x such that (a * x) % m == 1
    
    Raises:
        ValueError: If gcd(a, m) != 1 (no inverse exists)
    """
    gcd, x, _ = extended_euclidean(a, m)
    
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for a={a}, m={m}")
    
    return (x % m + m) % m


def gcd(a, b):
    """
    Compute Greatest Common Divisor using Euclidean algorithm.
    
    Args:
        a: First number
        b: Second number
    
    Returns:
        gcd(a, b)
    """
    while b:
        a, b = b, a % b
    return a


# ============================================================================
# PHASE 1.2: Prime Number Generation
# ============================================================================

def is_prime_miller_rabin(n, k=40):
    """
    Miller-Rabin primality test.
    
    Probabilistic test with error probability 4^(-k).
    
    Args:
        n: Number to test for primality
        k: Number of rounds (40 gives ~2^(-80) error probability)
    
    Returns:
        True if probably prime, False if definitely composite
    """
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
    """
    Generate a random prime of specified bit length.
    
    Uses Miller-Rabin test with rejection sampling.
    
    Args:
        bit_length: Desired bit length (e.g., 2048 or 3072)
    
    Returns:
        A prime p where 2^(bit_length-1) < p < 2^bit_length
    """
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
    """
    Find a primitive root (generator) modulo p.
    
    A generator g generates all non-zero elements mod p.
    i.e., g has order p-1.
    
    Algorithm: Check if g^((p-1)/q) != 1 (mod p) for all prime factors q of (p-1).
    
    Args:
        p: Prime modulus
    
    Returns:
        A generator g modulo p
    """
    # For security, we need p-1 to have small factors
    # Simplified: just check g^((p-1)/2) != 1 and g^((p-1)/q) != 1
    # for small prime factors
    
    p_minus_1 = p - 1
    
    # Find prime factors of p-1 (simplified for common case)
    factors = set()
    temp = p_minus_1
    
    # Check for factor 2
    while temp % 2 == 0:
        factors.add(2)
        temp //= 2
    
    # Check for odd factors (simplified - just check a few)
    d = 3
    while d * d <= temp and len(factors) < 10:
        while temp % d == 0:
            factors.add(d)
            temp //= d
        d += 2
    
    if temp > 1:
        factors.add(temp)
    
    # Test candidates for generator
    for g in range(2, min(p, 1000)):
        is_generator = True
        
        for factor in factors:
            exponent = p_minus_1 // factor
            if modular_exponentiation(g, exponent, p) == 1:
                is_generator = False
                break
        
        if is_generator:
            return g
    
    # Fallback: if p is small, do exhaustive search
    for g in range(2, p):
        is_generator = True
        for factor in factors:
            exponent = p_minus_1 // factor
            if modular_exponentiation(g, exponent, p) == 1:
                is_generator = False
                break
        if is_generator:
            return g
    
    return 2  # Fallback


# ============================================================================
# PHASE 1.3: ElGamal Key Generation
# ============================================================================

class ElGamalKey:
    """Container for ElGamal public/private keys."""
    
    def __init__(self, p, g, x=None, y=None, sl=None):
        """
        Initialize ElGamal key.
        
        Args:
            p: Prime modulus
            g: Generator
            x: Private key (secret exponent)
            y: Public key (g^x mod p)
            sl: Security level (bit length of p)
        """
        self.p = p
        self.g = g
        self.x = x          # Private key
        self.y = y          # Public key
        self.sl = sl or p.bit_length()
    
    def is_private(self):
        """Check if this key contains private component."""
        return self.x is not None
    
    def is_public(self):
        """Check if this key contains public component."""
        return self.y is not None


def generate_elgamal_keypair(p, g):
    """
    Generate ElGamal key pair.
    
    Args:
        p: Prime modulus
        g: Generator
    
    Returns:
        ElGamalKey object with both public and private components
    """
    # Generate random private key x in [1, p-2]
    x = random.randint(1, p - 2)
    
    # Compute public key y = g^x mod p
    y = modular_exponentiation(g, x, p)
    
    return ElGamalKey(p, g, x=x, y=y)


# ============================================================================
# PHASE 1.4: ElGamal Encryption/Decryption
# ============================================================================

def elgamal_encrypt(message, public_key):
    """
    ElGamal Encryption.
    
    Encrypts message m to ciphertext (c1, c2).
    
    Args:
        message: Integer message m (must be < p)
        public_key: ElGamalKey with (p, g, y)
    
    Returns:
        Tuple (c1, c2) where:
            c1 = g^k mod p
            c2 = (m * y^k) mod p
    """
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
    """
    ElGamal Decryption.
    
    Decrypts ciphertext (c1, c2) using private key x.
    
    Args:
        ciphertext: Tuple (c1, c2)
        private_key: ElGamalKey with (p, g, x)
    
    Returns:
        Original message m = c2 * (c1^x)^(-1) mod p
    """
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
# PHASE 1.5: ElGamal Digital Signatures
# ============================================================================

def elgamal_sign(message_hash, private_key):
    """
    ElGamal Digital Signature.
    
    Signs a message hash.
    
    Args:
        message_hash: Integer hash H(m) of the message (< p)
        private_key: ElGamalKey with (p, g, x)
    
    Returns:
        Signature tuple (r, s) where:
            r = g^k mod p
            s = (H(m) - x*r) * k^(-1) mod (p-1)
    """
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
    """
    ElGamal Signature Verification.
    
    Verifies a signature on a message hash.
    
    Args:
        message_hash: Integer hash H(m)
        signature: Tuple (r, s)
        public_key: ElGamalKey with (p, g, y)
    
    Returns:
        True if valid, False otherwise
    
    Verification: Check if g^H(m) ≡ y^r * r^s (mod p)
    """
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
# PHASE 1.6: Hash and MAC Functions
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
    """
    HMAC-SHA256 authentication code.
    
    Args:
        key: Secret key (bytes or string)
        data: Message to authenticate (bytes or string)
    
    Returns:
        bytes (32-byte HMAC)
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hmac.new(key, data, hashlib.sha256).digest()


# ============================================================================
# PHASE 1.7: AES-256 CBC Mode Encryption/Decryption
# ============================================================================

def aes_encrypt(key, plaintext):
    """
    AES-256 encryption in CBC mode.
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt (bytes or string)
    
    Returns:
        (iv, ciphertext) tuple both as bytes
    """
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
    """
    AES-256 decryption in CBC mode.
    
    Args:
        key: 32-byte encryption key
        iv: 16-byte initialization vector
        ciphertext: Encrypted data (bytes)
    
    Returns:
        Original plaintext (bytes)
    """
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
# PHASE 1.8: Message Encoding/Decoding
# ============================================================================

def bytes_to_int(data):
    """Convert bytes to integer for ElGamal encryption."""
    return int.from_bytes(data, byteorder='big')


def int_to_bytes(n, length=None):
    """
    Convert integer back to bytes.
    
    Args:
        n: Integer to convert
        length: Optional fixed byte length
    
    Returns:
        bytes representation
    """
    if length is None:
        length = (n.bit_length() + 7) // 8
        if length == 0:
            length = 1
    return n.to_bytes(length, byteorder='big')


def split_message(message, chunk_size):
    """
    Split large message into chunks for ElGamal encryption.
    
    Args:
        message: bytes to split
        chunk_size: Maximum chunk size in bytes
    
    Returns:
        List of byte chunks
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    chunks = []
    for i in range(0, len(message), chunk_size):
        chunks.append(message[i:i + chunk_size])
    
    return chunks


def join_chunks(chunks):
    """Reassemble message from chunks."""
    return b''.join(chunks)


# ============================================================================
# Utility Functions for Protocol
# ============================================================================

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


def serialize_key(key):
    """Serialize ElGamal key to bytes."""
    result = int_to_bytes_variable(key.p)
    result += int_to_bytes_variable(key.g)
    if key.x is not None:
        result += b'\x01' + int_to_bytes_variable(key.x)
    else:
        result += b'\x00'
    if key.y is not None:
        result += int_to_bytes_variable(key.y)
    return result


def deserialize_key(data, include_private=False):
    """Deserialize ElGamal key from bytes."""
    offset = 0
    p, offset = bytes_from_int_variable(data, offset)
    g, offset = bytes_from_int_variable(data, offset)
    
    x = None
    has_x = data[offset]
    offset += 1
    if has_x and include_private:
        x, offset = bytes_from_int_variable(data, offset)
    elif has_x:
        _, offset = bytes_from_int_variable(data, offset)
    
    y = None
    if offset < len(data):
        y, offset = bytes_from_int_variable(data, offset)
    
    return ElGamalKey(p, g, x=x, y=y)


# ============================================================================
# Testing Functions
# ============================================================================

def test_modular_exponentiation():
    """Test modular exponentiation with known values."""
    assert modular_exponentiation(3, 5, 7) == 5, "3^5 mod 7 should be 5"
    assert modular_exponentiation(2, 10, 1000) == 24, "2^10 mod 1000 should be 24"
    print("✓ Modular exponentiation tests passed")


def test_modular_inverse():
    """Test modular inverse computation."""
    inv = modular_inverse(3, 11)
    assert (3 * inv) % 11 == 1, "3 * inv(3,11) mod 11 should be 1"
    
    inv = modular_inverse(7, 26)
    assert (7 * inv) % 26 == 1, "7 * inv(7,26) mod 26 should be 1"
    print("✓ Modular inverse tests passed")


def test_elgamal():
    """Test ElGamal encryption/decryption with small prime."""
    # Use small prime for fast testing
    p = 61
    g = 2
    keypair = generate_elgamal_keypair(p, g)
    
    # Test encryption/decryption
    message = 42
    ciphertext = elgamal_encrypt(message, keypair)
    decrypted = elgamal_decrypt(ciphertext, keypair)
    assert message == decrypted, f"Encrypt/decrypt failed: {message} != {decrypted}"
    
    # Test signatures
    msg_hash = 50
    signature = elgamal_sign(msg_hash, keypair)
    valid = elgamal_verify(msg_hash, signature, keypair)
    assert valid, "Signature verification failed"
    
    # Test invalid signature
    invalid = elgamal_verify(msg_hash + 1, signature, keypair)
    assert not invalid, "Invalid signature should not verify"
    
    print("✓ ElGamal tests passed")


def test_aes():
    """Test AES encryption/decryption."""
    key = b'a' * 32
    plaintext = b"Hello, World! This is a test message."
    
    iv, ciphertext = aes_encrypt(key, plaintext)
    decrypted = aes_decrypt(key, iv, ciphertext)
    
    assert plaintext == decrypted, "AES encrypt/decrypt failed"
    print("✓ AES tests passed")


def test_hash_hmac():
    """Test hash and HMAC functions."""
    data = b"test data"
    h = hash_sha256(data)
    assert len(h) == 32, "SHA256 should produce 32 bytes"
    assert h == hash_sha256(data), "Hash should be deterministic"
    
    key = b"secret"
    mac = hmac_sha256(key, data)
    assert len(mac) == 32, "HMAC-SHA256 should produce 32 bytes"
    assert mac == hmac_sha256(key, data), "HMAC should be deterministic"
    assert mac != hmac_sha256(b"different", data), "Different key should give different HMAC"
    
    print("✓ Hash and HMAC tests passed")


if __name__ == "__main__":
    print("Running crypto utility tests...")
    test_modular_exponentiation()
    test_modular_inverse()
    test_elgamal()
    test_aes()
    test_hash_hmac()
    print("\n✓ All crypto tests passed!")
