# SNS Assignment 1: Secure Client-Server Protocol Implementation

## Overview

This project implements a secure client-server protocol designed to withstand various active network attacks. The protocol features symmetric encryption (AES-128-CBC), HMAC-SHA256 for integrity verification, key ratcheting for forward secrecy, and strict round-based sequencing to prevent replay and reordering attacks.

The server aggregates numeric data from multiple concurrent clients per round, computing the product of sums (or byte lengths for non-numeric data) across all connected clients.

## Key Security Features

- **Confidentiality**: AES-128-CBC encryption with random IVs
- **Integrity & Authentication**: HMAC-SHA256 verification
- **Forward Secrecy**: Per-message key evolution (ratcheting)
- **Replay Protection**: Strict round number validation
- **Reflection Defense**: Directional packet validation
- **Desynchronization Prevention**: State machine enforcement

## Architecture

### Core Components

- **`protocol_fsm.py`**: Finite state machine managing protocol logic, packet construction/validation, and key management
- **`server.py`**: Multi-threaded server handling client connections and data aggregation
- **`client.py`**: Client application for secure communication
- **`crypto_utils.py`**: Cryptographic primitives (AES, HMAC, padding)
- **`attacks.py`**: Man-in-the-Middle proxy for attack simulation

### Protocol Flow

1. **Client Hello** (Round 0): Client initiates with OP_HELLO
2. **Server Challenge** (Round 0): Server responds with OP_CHALLENGE
3. **Data Exchange Loop** (Rounds 1+):
   - Client sends OP_DATA with payload
   - Server aggregates data and responds with OP_AGGR_RESP
   - Keys ratchet after each message exchange
   - Round increments after successful exchange

### Packet Structure

```
Header (7 bytes): Opcode(1) | ClientID(1) | Round(4) | Direction(1)
IV (16 bytes): Random initialization vector
Ciphertext (variable): AES-128-CBC encrypted payload with PKCS#7 padding
HMAC (32 bytes): SHA256 HMAC over header + IV + ciphertext
```

## Installation & Setup

### Prerequisites

- Python 3.8+
- `cryptography` library

### Installation

```bash
pip install cryptography
```

## Usage

### Running the Server

```bash
python server.py
```

The server listens on `127.0.0.1:65432` and supports up to 100 clients with pre-shared keys.

### Running a Client

```bash
python client.py
```

Each client gets a random ID (1-100) and connects to `127.0.0.1:65433`. Enter messages when prompted, or type 'exit' to quit.

### Testing Attacks with MITM Proxy

To simulate attacks, run the proxy between client and server:

```bash
python attacks.py
```

The proxy listens on `127.0.0.1:65433` and forwards traffic to the server on `127.0.0.1:65432`.

Available attack commands in the proxy interface:
- `r`: Replay attack (sends packet twice)
- `t`: Tamper attack (corrupts ciphertext)
- `d`: Drop attack (causes desynchronization)
- `f`: Reflection attack (sends server response back to server)
- `c`: Cancel pending attack

## Key Management

- **Master Keys**: Derived from base key + client ID using SHA256
- **Session Keys**: Separate C2S/S2C encryption and MAC keys
- **Key Evolution**: Keys ratchet using SHA256(current_key + message_data)
- **Forward Secrecy**: Old keys cannot be recovered from current keys

## Data Aggregation

- **Numeric Data**: Comma-separated integers are summed per client
- **Non-numeric Data**: Uses message byte length
- **Global Aggregation**: Product of all client aggregates per round
- **Thread Safety**: Protected with locks for concurrent access

## Security Analysis

The protocol defends against:

- **Replay Attacks**: Round number validation prevents duplicate processing
- **Tampering**: HMAC verification detects any modifications
- **Reordering**: Strict round sequencing enforced
- **Reflection**: Direction flags prevent misdirected packets
- **Key Compromise**: Ratcheting provides forward secrecy
- **Desynchronization**: State validation terminates compromised connections

## Files

- `protocol_fsm.py`: Protocol state machine and packet handling
- `server.py`: Server implementation with aggregation logic
- `client.py`: Client application
- `crypto_utils.py`: AES encryption, HMAC, and padding utilities
- `attacks.py`: MITM proxy for attack simulation
- `ReadMe.md`: This documentation
- `security.md`: Detailed security analysis
- `SNS_Lab_1.pdf`: Original assignment specification

## Notes

- Clients are identified by IDs 1-100 with pre-shared derived keys
- Aggregation resets per round across all connected clients
- All security violations result in immediate connection termination
- The protocol assumes secure initial key distribution