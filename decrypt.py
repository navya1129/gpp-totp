import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def decrypt_seed(encrypted_seed_b64: str, private_key):
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256)
    Returns 64-character hex seed
    """

    # Step 1: Base64 decode
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # Step 2: RSA/OAEP decrypt
    decrypted_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 3: Convert bytes → string
    seed = decrypted_bytes.decode("utf-8")

    # Step 4: Validate
    if len(seed) != 64:
        raise ValueError("Seed must be 64 hex chars!")

    if not all(c in "0123456789abcdef" for c in seed.lower()):
        raise ValueError("Seed contains non-hex characters!")

    return seed


# ---------- MAIN EXECUTION ----------
if __name__ == "__main__":
    encrypted_seed_b64 = open("encrypted_seed.txt").read().strip()

    private_key_data = open("student_private.pem", "rb").read()
    private_key = load_pem_private_key(private_key_data, password=None)

    seed_hex = decrypt_seed(encrypted_seed_b64, private_key)

    print("Decrypted seed:", seed_hex)

    # Step 5: Store in /data/seed.txt
    with open("data/seed.txt", "w") as f:
        f.write(seed_hex)

