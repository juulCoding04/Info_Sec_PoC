from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import json
import base64

def sign(data: dict, private_key) -> str:
    """
    Sign a dictionary (credentials or presentation data) using ECDSA P-256.
    In the real world this happens inside the TEE after hardware confirmed user presence.
    Returns a base64-encoded signature string
    """
    message = json.dumps(data, sort_keys=True).encode() # convert dict to JSON string and convert to bytes

    # 1. Hashing message using SHA256
    # 2. Then sign using ECDSA
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    return base64.b64encode(signature).decode()

def verify(data: dict, signature: str, public_key) -> bool:
    """
    Verify an ECDSA P-256 signature over a dictionary.
    Returns True if it's valid and False if not (tamper detection)
    """
    try:
        # try the inverse operation of the sign function to verify (using public key)
        message = json.dumps(data, sort_keys=True).encode()
        signature_bytes = base64.b64decode(signature)
        public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False # Data has been tampered with
