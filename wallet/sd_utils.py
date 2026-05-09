import sys
import os
import json
import base64
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def get_jwt_payload(cred: dict) -> dict:
    try:
        jwt = cred.get("jwt", "")
        payload_b64 = jwt.split(".")[1]
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode())
    except Exception:
        return {}

def decode_disclosure(encoded: str) -> tuple:
    """
    decode a base64 SD-JWT disclosure
    Returns (claim_name, claim_value)
    """
    padded = encoded + "=" * (4 - len(encoded) % 4)
    decoded = base64.urlsafe_b64decode(padded).decode()
    parts = json.loads(decoded) # parts = [salt, key, value]

    return parts[1], parts[2]

def disclosure_hash(encoded_disclosure: str) -> str:
    """
    Compute SD-JWT disclosure hash
    """
    temp = hashlib.sha256(encoded_disclosure.encode()).digest()
    return base64.urlsafe_b64encode(temp).rstrip(b"=").decode()

def verify_disclosures(cred: dict) -> bool:
    """
    Verify all disclosures match hashes in SD-JWT payload
    returns True if these match and False otherwise
    """
    payload = get_jwt_payload(cred)
    expected_hashes = payload.get("_sd", [])
    disclosures = cred.get("disclosures", {})

    for _, encoded in disclosures.items():
        h = disclosure_hash(encoded)

        if h not in expected_hashes:
            return False
    return True

def get_readable_disclosure(cred: dict) -> dict:
    readable = {}
    for key, enc in cred.get("disclosures", {}).items():
        try:
            claim_name, claim_value = decode_disclosure(enc)
            readable[claim_name] = claim_value
        except Exception:
            readable[key] = enc # fallback to raw encoded if decoding fails
    return readable

