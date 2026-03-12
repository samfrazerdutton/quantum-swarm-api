import base64, hashlib, json, os, time
from typing import Optional
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Quantum-Swarm PQC API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

drone_keys = {}
sessions = {}
nonce_log = set()
KEM_ALG = "ML-KEM-1024"
SIG_ALG = "ML-DSA-65"

def b64e(data): return base64.b64encode(data).decode()
def b64d(s): return base64.b64decode(s)

class DroneRegistration(BaseModel):
    drone_id: str
    role: str

class KEXInitRequest(BaseModel):
    initiator_id: str
    responder_id: str

class KEXCompleteRequest(BaseModel):
    session_id: str
    drone_id: str
    ciphertext: str

class SignTelemetryRequest(BaseModel):
    drone_id: str
    session_id: str
    payload: dict

class VerifyTelemetryRequest(BaseModel):
    sender_id: str
    session_id: str
    nonce: str
    encrypted_payload: str
    signature: str

@app.get("/")
def root():
    return {"service": "Quantum-Swarm PQC API", "kem": KEM_ALG, "sig": SIG_ALG, "drones": list(drone_keys.keys()), "sessions": len(sessions)}

@app.get("/algorithms")
def algorithms():
    return {"kem": oqs.get_enabled_kem_mechanisms(), "sig": oqs.get_enabled_sig_mechanisms()}

@app.post("/drone/register")
def register_drone(req: DroneRegistration):
    if req.drone_id in drone_keys:
        raise HTTPException(400, "Already registered. Use /drone/rotate to rekey.")
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_pk = kem.generate_keypair()
        kem_sk = kem.export_secret_key()
    with oqs.Signature(SIG_ALG) as sig:
        sig_pk = sig.generate_keypair()
        sig_sk = sig.export_secret_key()
    drone_keys[req.drone_id] = {"role": req.role, "kem_pk": kem_pk, "kem_sk": kem_sk, "sig_pk": sig_pk, "sig_sk": sig_sk, "registered_at": time.time()}
    return {"drone_id": req.drone_id, "kem_algorithm": KEM_ALG, "sig_algorithm": SIG_ALG, "kem_public_key": b64e(kem_pk), "sig_public_key": b64e(sig_pk)}

@app.post("/drone/rotate/{drone_id}")
def rotate_keys(drone_id: str):
    if drone_id not in drone_keys:
        raise HTTPException(404, "Drone not found.")
    role = drone_keys[drone_id]["role"]
    del drone_keys[drone_id]
    for sid in [s for s, v in sessions.items() if drone_id in (v["drone_a"], v["drone_b"])]:
        del sessions[sid]
    return register_drone(DroneRegistration(drone_id=drone_id, role=role))

@app.get("/drone/{drone_id}")
def get_drone(drone_id: str):
    if drone_id not in drone_keys:
        raise HTTPException(404, "Not found.")
    d = drone_keys[drone_id]
    return {"drone_id": drone_id, "role": d["role"], "kem_public_key": b64e(d["kem_pk"]), "sig_public_key": b64e(d["sig_pk"])}

@app.post("/kex/init")
def kex_init(req: KEXInitRequest):
    for did in (req.initiator_id, req.responder_id):
        if did not in drone_keys:
            raise HTTPException(404, f"Drone {did} not registered.")
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        ciphertext, shared_secret = kem.encap_secret(drone_keys[req.responder_id]["kem_pk"])
    session_id = hashlib.sha256(f"{req.initiator_id}{req.responder_id}{time.time()}".encode()).hexdigest()[:24]
    sessions[session_id] = {"drone_a": req.initiator_id, "drone_b": req.responder_id, "shared_key": shared_secret, "ciphertext": ciphertext, "created_at": time.time()}
    return {"session_id": session_id, "initiator_id": req.initiator_id, "responder_id": req.responder_id, "ciphertext": b64e(ciphertext)}

@app.post("/kex/complete")
def kex_complete(req: KEXCompleteRequest):
    if req.session_id not in sessions:
        raise HTTPException(404, "Session not found.")
    session = sessions[req.session_id]
    if req.drone_id != session["drone_a"]:
        raise HTTPException(403, "Only initiating drone may complete KEX.")
    with oqs.KeyEncapsulation(KEM_ALG, drone_keys[session["drone_b"]]["kem_sk"]) as kem:
        derived = kem.decap_secret(b64d(req.ciphertext))
    if derived != session["shared_key"]:
        raise HTTPException(400, "Key mismatch — possible MITM.")
    return {"session_id": req.session_id, "status": "established", "shared_key_fingerprint": hashlib.sha256(derived).hexdigest()}

@app.post("/telemetry/sign")
def sign_telemetry(req: SignTelemetryRequest):
    if req.drone_id not in drone_keys: raise HTTPException(404, "Drone not found.")
    if req.session_id not in sessions: raise HTTPException(404, "Session not found.")
    session = sessions[req.session_id]
    if req.drone_id not in (session["drone_a"], session["drone_b"]): raise HTTPException(403, "Not party to session.")
    nonce = os.urandom(12)
    aesgcm = AESGCM(session["shared_key"][:32])
    ciphertext = aesgcm.encrypt(nonce, json.dumps(req.payload, separators=(",",":")).encode(), None)
    with oqs.Signature(SIG_ALG, drone_keys[req.drone_id]["sig_sk"]) as signer:
        signature = signer.sign(nonce + ciphertext)
    return {"drone_id": req.drone_id, "session_id": req.session_id, "nonce": nonce.hex(), "encrypted_payload": b64e(ciphertext), "signature": b64e(signature), "timestamp": time.time()}

@app.post("/telemetry/verify")
def verify_telemetry(req: VerifyTelemetryRequest):
    if req.sender_id not in drone_keys: raise HTTPException(404, "Drone not found.")
    if req.session_id not in sessions: raise HTTPException(404, "Session not found.")
    replay_key = f"{req.session_id}:{req.nonce}"
    if replay_key in nonce_log:
        return {"valid": False, "reason": "REPLAY ATTACK: nonce already consumed.", "sig_verified": False, "replay_check": False}
    nonce_log.add(replay_key)
    nonce_bytes = bytes.fromhex(req.nonce)
    ciphertext = b64d(req.encrypted_payload)
    with oqs.Signature(SIG_ALG) as verifier:
        sig_valid = verifier.verify(nonce_bytes + ciphertext, b64d(req.signature), drone_keys[req.sender_id]["sig_pk"])
    if not sig_valid:
        return {"valid": False, "reason": "INVALID SIGNATURE: Dilithium3 verification failed.", "sig_verified": False, "replay_check": True}
    try:
        plaintext = AESGCM(sessions[req.session_id]["shared_key"][:32]).decrypt(nonce_bytes, ciphertext, None)
        return {"valid": True, "sender_id": req.sender_id, "decrypted_payload": json.loads(plaintext), "sig_verified": True, "replay_check": True}
    except Exception as e:
        return {"valid": False, "reason": f"DECRYPTION FAILED: {e}", "sig_verified": True, "replay_check": True}

@app.get("/sessions")
def list_sessions():
    return {sid: {"drone_a": s["drone_a"], "drone_b": s["drone_b"], "fingerprint": hashlib.sha256(s["shared_key"]).hexdigest()} for sid, s in sessions.items()}
