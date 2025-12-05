#!/usr/bin/env python3
import os
import base64
from datetime import datetime, timezone
import pyotp

SEED_FILE = "/data/seed.txt"

def generate_totp(hex_seed: str) -> str:
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode()
    totp = pyotp.TOTP(base32_seed)
    return totp.now()

def main():
    if not os.path.exists(SEED_FILE):
        print("Seed file not found")
        return

    with open(SEED_FILE, "r") as f:
        hex_seed = f.read().strip()

    try:
        code = generate_totp(hex_seed)
    except Exception as e:
        print(f"Error generating TOTP: {e}")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - 2FA Code: {code}")

if __name__ == "__main__":
    main()
