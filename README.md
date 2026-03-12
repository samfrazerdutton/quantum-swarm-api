# Quantum-Swarm PQC Security API

A production-ready post-quantum cryptography API built on the NIST 2024 standards.
Secures any client-to-client communication against both classical and quantum computer attacks.

## Demo Output
```
=== Quantum-Swarm PQC End-to-End Demo ===

[OK] Server online: Quantum-Swarm PQC API

-- Step 1: Register Clients --
[OK] DRONE-001 registered in 6.7ms
     KEM pk: vGASgFUQ2AJh2Lqiz9GNP4d4bDFY3Te+j7B/U9S+p0mrkICi...
     SIG pk: ImFA4OQ0Tm/7lejoIpF8zKE2pCToePkAFwHPWTYbgTtrY6CK...

-- Step 2: Kyber-1024 Key Exchange --
[OK] Encapsulation in 3.9ms
[OK] Decapsulation in 4.8ms | status: established
     Shared key fingerprint: f3f4069c98993c3ac3258b9b69c7d89a8647c1534ac487536b3f43d6c1eb3fc3

-- Step 3: Sign + Encrypt Payload --
[OK] Signed + encrypted in 6.0ms
     Nonce:      a4e9464f874295d89e72b651
     Ciphertext: WXvXMnLK/5amJ7OHF/WSM2t+8AO6KsR6TAHnzkxmBDuc...
     Signature:  BCTZM+j1W+kb20g0wMV7Elp83JJ7eWwKR/BG5LTWOsN1...

-- Step 4: Verify + Decrypt --
[OK] Verified in 4.6ms | sig_ok=True replay_ok=True
     Payload: {'lat': 51.5074, 'lon': -0.1278, 'alt_m': 120.5, 'speed_ms': 8.2, 'status': 'NOMINAL'}

-- Step 5: Replay Attack --
[BLOCKED] REPLAY ATTACK: nonce already consumed.

-- Step 6: Tampered Signature --
[BLOCKED] INVALID SIGNATURE: Dilithium3 verification failed.

=== Demo complete ===
```

## What This Is

RSA and ECDSA — the encryption standards protecting virtually everything on the internet today —
are broken by a quantum computer running Shor's algorithm. NIST spent 7 years running a global
competition to find replacements and published the winners in August 2024.

This is a working REST API implementation of those standards.

## Algorithms

| Algorithm | Type | Standard | Security |
|---|---|---|---|
| CRYSTALS-Kyber-1024 | Key Encapsulation | FIPS 203 | L5 / 256-bit |
| ML-DSA-65 (Dilithium) | Digital Signature | FIPS 204 | L3 / 128-bit |
| AES-256-GCM | Symmetric Encryption | — | 256-bit |

## What It Does

- **Quantum-safe key exchange** — two clients derive a shared secret using Kyber KEM.
  Security comes from the Module Learning With Errors (M-LWE) problem.
  No known quantum algorithm breaks this, including Shor's.
- **Authenticated encryption** — payloads encrypted with AES-256-GCM using the Kyber-derived key
- **Digital signatures** — every message signed with ML-DSA-65, cryptographically bound to sender identity
- **Replay attack protection** — per-session nonce log, stale packets rejected
- **Key rotation** — in-flight rekeying supported, old sessions invalidated

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/drone/register` | Generate Kyber + ML-DSA keypairs for a client |
| POST | `/drone/rotate/{id}` | Rotate keypairs |
| GET  | `/drone/{id}` | Get client public keys |
| POST | `/kex/init` | Kyber-1024 encapsulation — initiate key exchange |
| POST | `/kex/complete` | Kyber-1024 decapsulation — derive shared secret |
| POST | `/telemetry/sign` | Sign + encrypt a payload |
| POST | `/telemetry/verify` | Verify signature + decrypt + replay check |

Interactive docs at `http://localhost:8000/docs` when running.

## Setup

### Quickstart (Docker)
```bash
docker build -t quantum-swarm-api .
docker run -p 8000:8000 quantum-swarm-api
```

### Manual (Linux / WSL)

**1. Build liboqs**
```bash
sudo apt-get install -y cmake gcc ninja-build libssl-dev git
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
ninja && sudo ninja install && sudo ldconfig
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Run**
```bash
uvicorn main:app --reload --port 8000
```

**4. Run the demo**
```bash
python3 demo.py
```

## Security Model
```
CLIENT-A                          SERVER / CLIENT-B
   |                                      |
   |-- POST /drone/register ------------->|  Kyber-1024 + ML-DSA-65 keygen
   |<- kem_pk, sig_pk (public) -----------|
   |                                      |
   |-- POST /kex/init ------------------->|  Encap(responder_kem_pk) -> ct, K
   |<- ciphertext, session_id ------------|
   |                                      |
   |-- POST /kex/complete (ct) ---------->|  Decap(kem_sk, ct) -> K
   |   Both sides now hold K              |  Never transmitted. Quantum-safe.
   |                                      |
   |-- POST /telemetry/sign ------------->|  AES-256-GCM encrypt(K, payload)
   |                                      |  ML-DSA-65 sign(nonce || ciphertext)
   |<- encrypted_payload, signature ------|
   |                                      |
   |-- POST /telemetry/verify ----------->|  1. Nonce check (anti-replay)
   |                                      |  2. ML-DSA-65 verify signature
   |<- valid: true, decrypted_payload ----|  3. AES-256-GCM decrypt
```

## Threat Coverage

| Attack | Status | Mechanism |
|---|---|---|
| Shor's algorithm (quantum) | Blocked | Kyber hardness from M-LWE |
| Grover's algorithm (quantum) | Blocked | AES-256 key size |
| Man-in-the-Middle | Blocked | ML-DSA signature bound to identity |
| Replay attack | Blocked | Per-session nonce log |
| Tampered payload | Blocked | AES-GCM authentication tag |
| Key compromise | Mitigated | /rotate endpoint, session invalidation |

## Built On

- [Open Quantum Safe / liboqs](https://openquantumsafe.org) — NIST reference implementation
- [FastAPI](https://fastapi.tiangolo.com)
- [cryptography](https://cryptography.io)

## Author

**Sam Frazer-Dutton** — [github.com/samfrazerdutton](https://github.com/samfrazerdutton)

Part of the [Quantum-Swarm](https://github.com/samfrazerdutton/Quantum-Swarm) project —
a hybrid VQC drone controller secured by this PQC layer.
