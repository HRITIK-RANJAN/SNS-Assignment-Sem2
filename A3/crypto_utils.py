"""
crypto_utils.py
===============
All cryptographic primitives implemented manually (no asymmetric libs).

Implements:
  - Modular exponentiation (square-and-multiply)
  - Modular inverse (extended Euclidean)
  - Miller-Rabin primality test
  - Safe-prime / Schnorr group parameter generation
  - SHA-256 hashing (via hashlib — permitted as a hash primitive)
  - AES-256-CBC with manual PKCS#7 padding
  - Secure random sampling over Zq
  - Schnorr partial signature generation + combination + verification
"""

import os
import hashlib
import struct
import secrets


# ─────────────────────────────────────────────
# 1.  BASIC MODULAR ARITHMETIC
# ─────────────────────────────────────────────

def modpow(base: int, exp: int, mod: int) -> int:
    """
    Square-and-multiply modular exponentiation.
    Computes base^exp mod mod in O(log exp) multiplications.
    Never calls the built-in pow() with three arguments — implemented
    manually to satisfy the assignment requirement.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:               # if current bit is 1
            result = (result * base) % mod
        exp >>= 1                 # shift right
        base = (base * base) % mod
    return result


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (gcd, x, y) s.t. a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m (requires gcd(a,m)=1)."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"modinv: gcd({a},{m})={g} ≠ 1 — inverse does not exist")
    return x % m


def mod_add(a: int, b: int, q: int) -> int:
    return (a + b) % q


def mod_sub(a: int, b: int, q: int) -> int:
    return (a - b) % q


def mod_mul(a: int, b: int, q: int) -> int:
    return (a * b) % q


# ─────────────────────────────────────────────
# 2.  PRIMALITY TESTING (Miller-Rabin)
# ─────────────────────────────────────────────

def miller_rabin(n: int, rounds: int = 20) -> bool:
    """Probabilistic primality test. False-positive probability ≤ 4^-rounds."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2   # a in [2, n-2]
        x = modpow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = modpow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_prime(n: int) -> bool:
    return miller_rabin(n, rounds=25)


# ─────────────────────────────────────────────
# 3.  SCHNORR GROUP PARAMETER GENERATION
# ─────────────────────────────────────────────

def generate_schnorr_params(q_bits: int = 256, p_bits: int = 1024) -> tuple[int, int, int]:
    """
    Generate Schnorr group parameters (p, q, g) where:
      - q is a q_bits-bit prime
      - p = k*q + 1 is a p_bits-bit prime  (q | p-1)
      - g is a generator of the q-order subgroup of Z*_p

    Using 256-bit q and 1024-bit p gives ~128-bit security for DL.
    For faster demos you can lower these (e.g., 128 / 512).
    """
    print(f"[keygen] Generating {q_bits}-bit prime q …", flush=True)
    while True:
        q = secrets.randbits(q_bits - 1) | (1 << (q_bits - 1)) | 1  # odd, correct bit-length
        if is_prime(q):
            break

    print(f"[keygen] Generating {p_bits}-bit safe prime p = k*q+1 …", flush=True)
    while True:
        # k must be even so p-1 = k*q has factor 2
        k = secrets.randbits(p_bits - q_bits)
        k = k | 1  # make k odd so k*q is odd → p = k*q+1 is even+1 = odd? 
        # Actually: p odd requires k*q even.  q is odd, so k must be even.
        k = k & ~1 | 2   # make k even and ≥ 2
        p = k * q + 1
        if p.bit_length() == p_bits and is_prime(p):
            break

    print("[keygen] Finding generator g …", flush=True)
    while True:
        h = secrets.randbelow(p - 2) + 2   # h in [2, p-1]
        g = modpow(h, (p - 1) // q, p)
        if g != 1:
            break   # g has order q in Z*_p

    print(f"[keygen] Done.  q={q_bits} bits, p={p_bits} bits")
    return p, q, g


# ─────────────────────────────────────────────
# 4.  SECURE RANDOM SAMPLING
# ─────────────────────────────────────────────

def secure_random_zq(q: int) -> int:
    """
    Uniformly random element of Z*_q = {1, …, q-1}.
    Uses OS-level CSPRNG (os.urandom via secrets module).
    """
    while True:
        r = secrets.randbelow(q)
        if r != 0:
            return r


# ─────────────────────────────────────────────
# 5.  SHA-256 HASHING
# ─────────────────────────────────────────────

def sha256_bytes(data: bytes) -> bytes:
    """Return raw 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def sha256_int(data: bytes) -> int:
    """Return SHA-256 digest as a big-endian integer."""
    return int.from_bytes(sha256_bytes(data), "big")


def hash_message_R(message: bytes, R: int) -> int:
    """
    Schnorr challenge:  e = H(m || R)
    R is serialised as a big-endian 128-byte integer (fits 1024-bit p).
    """
    R_bytes = R.to_bytes(128, "big")
    return sha256_int(message + R_bytes)


# ─────────────────────────────────────────────
# 6.  AES-256-CBC  (manual PKCS#7)
# ─────────────────────────────────────────────

# We implement AES by wrapping Python's `cryptography` package for the
# block cipher primitive only.  The PKCS#7 padding, IV generation, and
# CBC chaining are all done manually here.

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


def _aes_ecb_block(key: bytes, block: bytes, encrypt: bool) -> bytes:
    """Single AES-256 block operation (ECB mode for one block)."""
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError("Install 'cryptography' package: pip install cryptography")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    if encrypt:
        enc = cipher.encryptor()
        return enc.update(block) + enc.finalize()
    else:
        dec = cipher.decryptor()
        return dec.update(block) + dec.finalize()


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Manual PKCS#7 padding to block_size boundary."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Manual PKCS#7 unpadding with validation."""
    if not data:
        raise ValueError("pkcs7_unpad: empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"pkcs7_unpad: invalid pad byte {pad_len}")
    for b in data[-pad_len:]:
        if b != pad_len:
            raise ValueError("pkcs7_unpad: inconsistent padding bytes")
    return data[:-pad_len]


def aes256_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CBC encryption with manual PKCS#7 and random IV.
    Returns:  IV (16 bytes) || ciphertext
    """
    assert len(key) == 32, "AES-256 requires 32-byte key"
    iv = os.urandom(16)
    padded = pkcs7_pad(plaintext, 16)
    ciphertext = b""
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc_block = _aes_ecb_block(key, block, encrypt=True)
        ciphertext += enc_block
        prev = enc_block
    return iv + ciphertext


def aes256_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    """
    AES-256-CBC decryption with manual PKCS#7 unpadding.
    Input:  IV (16 bytes) || ciphertext
    """
    assert len(key) == 32, "AES-256 requires 32-byte key"
    assert len(data) >= 32, "Data too short"
    iv = data[:16]
    ciphertext = data[16:]
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length not a multiple of 16")
    plaintext_padded = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec_block = _aes_ecb_block(key, block, encrypt=False)
        plaintext_padded += bytes(a ^ b for a, b in zip(dec_block, prev))
        prev = block
    return pkcs7_unpad(plaintext_padded)


def derive_aes_key(secret: int, label: bytes = b"session") -> bytes:
    """Derive a 32-byte AES key from an integer secret via SHA-256."""
    raw = secret.to_bytes((secret.bit_length() + 7) // 8, "big")
    return sha256_bytes(label + raw)


# ─────────────────────────────────────────────
# 7.  THRESHOLD SCHNORR SIGNATURES
# ─────────────────────────────────────────────

class SchnorrParams:
    """Container for public Schnorr group parameters."""
    def __init__(self, p: int, q: int, g: int):
        self.p = p
        self.q = q
        self.g = g

    def to_dict(self) -> dict:
        return {"p": self.p, "q": self.q, "g": self.g}

    @classmethod
    def from_dict(cls, d: dict) -> "SchnorrParams":
        return cls(int(d["p"]), int(d["q"]), int(d["g"]))


def schnorr_keygen(params: SchnorrParams) -> tuple[int, int]:
    """
    Generate individual keypair.
    Returns (x, y) where y = g^x mod p.
    """
    x = secure_random_zq(params.q)
    y = modpow(params.g, x, params.p)
    return x, y


def partial_sign(params: SchnorrParams, x_share: int, k: int, e: int) -> int:
    """
    Compute partial Schnorr signature share:
        s_i = k_i + e * x_i  mod q

    k   : per-signing nonce (MUST be unique per message, per signer)
    e   : Schnorr challenge = H(m || R_combined)
    """
    return (k + e * x_share) % params.q


def combine_partial_sigs(params: SchnorrParams, si: int, sj: int) -> int:
    """
    Combine two Lagrange-weighted partial signatures:
        s = s_i + s_j  mod q

    where s_i = k_i + e * lambda_i * x_i  (Lagrange-weighted partial sig)
    so s_i + s_j = (k_i+k_j) + e*(lambda_i*x_i + lambda_j*x_j)
                 = k_combined + e*x    (since Lagrange interpolation gives x)
    """
    return (si + sj) % params.q


# ── Shamir's Secret Sharing (2-of-3) ──────────────────────────────────────────

def shamir_split(x: int, q: int) -> tuple:
    """
    2-of-3 Shamir Secret Sharing over Z_q.

    Defines degree-1 polynomial f(t) = x + a*t  mod q
    Shares: x_i = f(i) for i = 1, 2, 3

    Any 2 shares allow Lagrange interpolation to recover x = f(0).
    A single share reveals nothing about x (uniformly random in Z_q).
    """
    a = secure_random_zq(q)          # random slope — kept secret
    x1 = (x + a * 1) % q            # f(1)
    x2 = (x + a * 2) % q            # f(2)
    x3 = (x + a * 3) % q            # f(3)
    return x1, x2, x3


def lagrange_coeff(i: int, j: int, q: int) -> tuple:
    """
    Lagrange basis coefficients at t=0 for the pair (i, j).

    For 2-of-3 Shamir at nodes with indices i, j ∈ {1,2,3}:

        lambda_i = j / (j - i)   mod q
        lambda_j = i / (i - j)   mod q

    so that lambda_i * f(i) + lambda_j * f(j) = f(0) = x.
    """
    lam_i = (j * modinv(j - i, q)) % q
    lam_j = (i * modinv(i - j, q)) % q
    return lam_i, lam_j


def shamir_partial_sign(params: SchnorrParams, x_share: int, share_index: int,
                         partner_index: int, k: int, e: int) -> int:
    """
    Lagrange-weighted partial Schnorr signature:
        s_i = k_i + e * lambda_i * x_i  mod q

    share_index   : this signer's index (1, 2, or 3)
    partner_index : the other signer's index
    k             : per-signing nonce (MUST be fresh each time)
    e             : Schnorr challenge = H(m || R_combined)
    """
    lam_i, _ = lagrange_coeff(share_index, partner_index, params.q)
    return (k + e * lam_i * x_share) % params.q


def shamir_verify_partial(params: SchnorrParams, x_share: int, share_index: int,
                           partner_index: int, k_i: int, R_i: int,
                           e: int, s_i: int) -> bool:
    """
    Verify a partial signature against the signer's own public share.
    Allows clients to detect a malicious/incorrect partial sig before combining.

    Checks: g^s_i == R_i * (g^x_i)^(lambda_i * e)  mod p
    """
    lam_i, _ = lagrange_coeff(share_index, partner_index, params.q)
    y_i      = modpow(params.g, x_share, params.p)   # public share (known to client)
    lhs = modpow(params.g, s_i, params.p)
    rhs = (R_i * modpow(y_i, (lam_i * e) % params.q, params.p)) % params.p
    return lhs == rhs


def shamir_pubshare(params: SchnorrParams, x_share: int) -> int:
    """Public share: y_i = g^x_i mod p."""
    return modpow(params.g, x_share, params.p)


def verify_threshold_signature(
    params: SchnorrParams,
    y_master: int,
    message: bytes,
    R_combined: int,
    s_combined: int,
) -> bool:
    """
    Verify 2-of-3 threshold Schnorr signature:
        g^s  ≡  R * y^e  (mod p)

    where e = H(m || R_combined).
    """
    e = hash_message_R(message, R_combined)
    lhs = modpow(params.g, s_combined, params.p)
    rhs = (R_combined * modpow(y_master, e, params.p)) % params.p
    return lhs == rhs


def combine_nonce_commitments(params: SchnorrParams, Ri: int, Rj: int) -> int:
    """
    Combine two nonce commitments:
        R = R_i * R_j  mod p

    This matches the additive nonce combination:
        k = k_i + k_j  →  g^k = g^(k_i+k_j) = g^k_i * g^k_j = R_i * R_j
    """
    return (Ri * Rj) % params.p


# ─────────────────────────────────────────────
# 8.  SERIALISATION HELPERS
# ─────────────────────────────────────────────

def int_to_hex(n: int) -> str:
    return hex(n)


def hex_to_int(h: str) -> int:
    return int(h, 16)


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)
