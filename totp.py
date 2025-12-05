import base64
import pyotp

def hex_to_base32(hex_seed: str) -> str:
    # Convert hex → bytes
    seed_bytes = bytes.fromhex(hex_seed)

    # Convert bytes → base32 → string
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8")

    return base32_seed


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed
    """

    base32_seed = hex_to_base32(hex_seed)

    # Create TOTP object (SHA-1, 30s, 6 digits)
    totp = pyotp.TOTP(base32_seed)

    # Generate code
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance
    """

    base32_seed = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed)

    # Verify with ±1 time step (±30 sec)
    return totp.verify(code, valid_window=valid_window)


if __name__ == "__main__":
    # Read decrypted seed from file
    with open("data/seed.txt", "r") as f:
        hex_seed = f.read().strip()

    print("Seed:", hex_seed)

    # Generate current TOTP
    code = generate_totp_code(hex_seed)
    print("Current TOTP Code:", code)

    # Test verification
    print("Verification:", verify_totp_code(hex_seed, code))
