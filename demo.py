import requests, time, base64, sys

BASE = "http://localhost:8000"

def post(path, body):
    r = requests.post(f"{BASE}{path}", json=body)
    r.raise_for_status()
    return r.json()

def get(path):
    r = requests.get(f"{BASE}{path}")
    r.raise_for_status()
    return r.json()

print("\n=== Quantum-Swarm PQC End-to-End Demo ===\n")

try:
    info = get("/")
    print(f"[OK] Server online: {info['service']}")
except:
    print("[ERR] Server not reachable. Is it running?")
    sys.exit(1)

print("\n-- Step 1: Register Drones --")
for d in [("DRONE-001","scout"), ("DRONE-002","relay")]:
    t0 = time.perf_counter()
    r = post("/drone/register", {"drone_id": d[0], "role": d[1]})
    ms = (time.perf_counter()-t0)*1000
    print(f"[OK] {d[0]} registered in {ms:.1f}ms")
    print(f"     KEM pk: {r['kem_public_key'][:48]}...")
    print(f"     SIG pk: {r['sig_public_key'][:48]}...")

print("\n-- Step 2: Kyber-1024 Key Exchange --")
t0 = time.perf_counter()
kex = post("/kex/init", {"initiator_id": "DRONE-001", "responder_id": "DRONE-002"})
ms = (time.perf_counter()-t0)*1000
sid = kex["session_id"]
print(f"[OK] Encapsulation in {ms:.1f}ms | session: {sid}")
print(f"     Ciphertext: {kex['ciphertext'][:64]}...")

t0 = time.perf_counter()
done = post("/kex/complete", {"session_id": sid, "drone_id": "DRONE-001", "ciphertext": kex["ciphertext"]})
ms = (time.perf_counter()-t0)*1000
print(f"[OK] Decapsulation in {ms:.1f}ms | status: {done['status']}")
print(f"     Shared key fingerprint: {done['shared_key_fingerprint']}")

print("\n-- Step 3: Sign + Encrypt Telemetry --")
payload = {"lat": 51.5074, "lon": -0.1278, "alt_m": 120.5, "speed_ms": 8.2, "battery_pct": 81, "status": "NOMINAL"}
t0 = time.perf_counter()
signed = post("/telemetry/sign", {"drone_id": "DRONE-001", "session_id": sid, "payload": payload})
ms = (time.perf_counter()-t0)*1000
print(f"[OK] Signed + encrypted in {ms:.1f}ms")
print(f"     Nonce:     {signed['nonce']}")
print(f"     Ciphertext: {signed['encrypted_payload'][:64]}...")
print(f"     Signature:  {signed['signature'][:64]}...")

print("\n-- Step 4: Verify + Decrypt --")
t0 = time.perf_counter()
v = post("/telemetry/verify", {"sender_id": "DRONE-001", "session_id": sid, "nonce": signed["nonce"], "encrypted_payload": signed["encrypted_payload"], "signature": signed["signature"]})
ms = (time.perf_counter()-t0)*1000
print(f"[OK] Verified in {ms:.1f}ms | sig_ok={v['sig_verified']} replay_ok={v['replay_check']}")
print(f"     Payload: {v['decrypted_payload']}")

print("\n-- Step 5: Replay Attack --")
r2 = post("/telemetry/verify", {"sender_id": "DRONE-001", "session_id": sid, "nonce": signed["nonce"], "encrypted_payload": signed["encrypted_payload"], "signature": signed["signature"]})
print(f"[{'BLOCKED' if not r2['valid'] else 'FAIL'}] {r2.get('reason','passed')}")

print("\n-- Step 6: Tampered Signature --")
fresh = post("/telemetry/sign", {"drone_id": "DRONE-001", "session_id": sid, "payload": {"tamper": "test"}})
sig_bytes = bytearray(base64.b64decode(fresh["signature"]))
sig_bytes[42] ^= 0xFF
bad_sig = base64.b64encode(bytes(sig_bytes)).decode()
r3 = post("/telemetry/verify", {"sender_id": "DRONE-001", "session_id": sid, "nonce": fresh["nonce"], "encrypted_payload": fresh["encrypted_payload"], "signature": bad_sig})
print(f"[{'BLOCKED' if not r3['valid'] else 'FAIL'}] {r3.get('reason','passed')}")

print("\n=== Demo complete ===\n")
