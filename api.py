import os
import base64
import time
import base64
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

app = FastAPI()

SEED_FILE = "data/seed.txt"
PRIVATE_KEY_FILE = "student_private.pem"

# ---------------------------
# Request Models
# ---------------------------

class DecryptRequest(BaseModel):
    encrypted_seed: str

class VerifyRequest(BaseModel):
    code: str


# ---------------------------
# Helper Functions
# ---------------------------

def decrypt_seed(encrypted_seed_b64: str) -> str:
    # Load private key
    with open(PRIVATE_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # Base64 decode
    encrypted = base64.b64decode(encrypted_seed_b64)

    # RSA-OAEP decrypt
    decrypted_bytes = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    hex_seed = decrypted_bytes.decode()

    # Validate: must be 64 hex chars
    if len(hex_seed) != 64 or any(c not in "0123456789abcdef" for c in hex_seed):
        raise ValueError("Invalid seed format")

    return hex_seed


def generate_totp(hex_seed: str) -> str:
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode()
    totp = pyotp.TOTP(base32_seed)
    return totp.now()


def read_seed():
    if not os.path.exists(SEED_FILE):
        return None
    with open(SEED_FILE, "r") as f:
        return f.read().strip()


# ---------------------------
# API Endpoints
# ---------------------------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(data: DecryptRequest):
    try:
        hex_seed = decrypt_seed(data.encrypted_seed)

        # Save seed
        with open(SEED_FILE, "w") as f:
            f.write(hex_seed)

        return {"status": "ok"}

    except Exception as e:
        return {"error": "Decryption failed"}


@app.get("/generate-2fa")
def generate_2fa():
    hex_seed = read_seed()
    if hex_seed is None:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    # Generate TOTP
    code = generate_totp(hex_seed)

    # Time remaining in this 30-second window
    valid_for = 30 - (int(time.time()) % 30)

    return {"code": code, "valid_for": valid_for}


@app.post("/verify-2fa")
def verify_2fa(data: VerifyRequest):
    if not data.code:
        raise HTTPException(status_code=400, detail="Missing code")

    hex_seed = read_seed()
    if hex_seed is None:
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    # Create TOTP
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode()
    totp = pyotp.TOTP(base32_seed)

    result = totp.verify(data.code, valid_window=1)

    return {"valid": result}
