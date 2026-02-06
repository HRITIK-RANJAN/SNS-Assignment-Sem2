import struct
import hashlib
from crypto_utils import encrypt_aes_128_cbc, decrypt_aes_128_cbc, compute_hmac, pad, unpad

# Constants & Opcodes

OP_HELLO = 10
OP_CHALLENGE = 20
OP_DATA = 30
OP_AGGR_RESP = 40
OP_ERROR = 50
OP_TERMINATE = 60

DIR_C2S = 0  # Client to Server
DIR_S2C = 1  # Server to Client

# Custom Exceptions for Strict Protocol Handling

class ProtocolError(Exception): pass
class DesyncError(ProtocolError): pass
class HMACError(ProtocolError): pass
class OpcodeError(ProtocolError): pass

class ProtocolState:
    def __init__(self, master_key: bytes, client_id: int):
        self.client_id = client_id
        self.round = 0
        self.master_key = master_key
        
        # Initialize Keys (Section 6)
        # Note: SHA256 is 32 bytes, AES key must be 16 bytes. We truncate for Enc, keep full for MAC.
        self.c2s_enc = self._hash(master_key + b"C2S-ENC")[:16]
        self.c2s_mac = self._hash(master_key + b"C2S-MAC")
        self.s2c_enc = self._hash(master_key + b"S2C-ENC")[:16]
        self.s2c_mac = self._hash(master_key + b"S2C-MAC")

    def _hash(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def construct_packet(self, opcode: int, payload: bytes, direction: int) -> bytes:
        """
        Encrypts payload and builds the packet:
        Header(6) | IV(16) | Ciphertext(Var) | HMAC(32)
        """
        # 1. Pad & Encrypt Payload
        padded_payload = pad(payload)
        
        # Select correct key based on direction
        key_enc = self.c2s_enc if direction == DIR_C2S else self.s2c_enc
        key_mac = self.c2s_mac if direction == DIR_C2S else self.s2c_mac
        
        iv, ciphertext = encrypt_aes_128_cbc(key_enc, padded_payload)
        
        # 2. Build Header: Opcode(1), ClientID(1), Round(4), Direction(1)
        # > = Big Endian, B = uchar(1), I = uint(4)
        header = struct.pack('>BBI B', opcode, self.client_id, self.round, direction)
        
        # 3. Compute HMAC over (Header || IV || Ciphertext)
        mac_input = header + iv + ciphertext
        mac_tag = compute_hmac(key_mac, mac_input)
        
        return header + iv + ciphertext + mac_tag

    def process_incoming_packet(self, packet: bytes, expected_direction: int) -> tuple:
        """
        Parses, Validates (Round, MAC), and Decrypts a packet.
        Returns: (opcode, plaintext_bytes)
        """
        MIN_LEN = 7 + 16 + 16 + 32 # Header + IV + MinBlock + MAC
        if len(packet) < MIN_LEN:
            raise ProtocolError("Packet too short")

        # Extract Fixed Length Parts
        header = packet[:7]
        opcode, client_id, rcv_round, rcv_dir = struct.unpack('>BBI B', header)
        
        iv = packet[7:23]
        mac_tag = packet[-32:]
        ciphertext = packet[23:-32]

        # 1. Validate State (Round & Direction)
        if rcv_round != self.round:
            raise DesyncError(f"Round mismatch: Expected {self.round}, Got {rcv_round}")
        if rcv_dir != expected_direction:
            raise ProtocolError(f"Wrong direction: Expected {expected_direction}, Got {rcv_dir}")
        if client_id != self.client_id:
            raise ProtocolError("Client ID mismatch")

        # 2. Validate HMAC
        key_mac = self.c2s_mac if rcv_dir == DIR_C2S else self.s2c_mac
        expected_mac = compute_hmac(key_mac, header + iv + ciphertext)
        
        if expected_mac != mac_tag:
            raise HMACError("HMAC Verification Failed! Tampering detected.")

        # 3. Decrypt
        key_enc = self.c2s_enc if rcv_dir == DIR_C2S else self.s2c_enc
        try:
            padded_plaintext = decrypt_aes_128_cbc(key_enc, iv, ciphertext)
            plaintext = unpad(padded_plaintext)
        except Exception as e:
            raise ProtocolError(f"Decryption failed: {e}")

        return opcode, plaintext

    def ratchet_keys(self, data_for_update: bytes, direction: int):
        """
        Updates keys for the NEXT round (R+1).
        Section 7: Keys must evolve using previous keys + some data.
        """
        if direction == DIR_C2S:
            # Client just sent message, update C2S keys
            self.c2s_enc = self._hash(self.c2s_enc + data_for_update)[:16]
            self.c2s_mac = self._hash(self.c2s_mac + b"nonce") # Simplified Nonce
        else:
            # Server just sent message, update S2C keys
            self.s2c_enc = self._hash(self.s2c_enc + data_for_update)[:16]
            self.s2c_mac = self._hash(self.s2c_mac + b"status")

        # Increment round only after a full exchange or as defined by your logic flow
        # For this assignment, we usually increment after a successful receive/send pair.
        # We will manually increment round in the server/client logic to keep it flexible.
    
    def increment_round(self):
        self.round += 1