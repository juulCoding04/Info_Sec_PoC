import json
import uuid
import base64
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
import base64

def _b64url(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _hash_disclosure(disclosure: str) -> str:
    """SHA-256 hash a disclosure string, base64url encoded."""
    digest = hashlib.sha256(disclosure.encode()).digest()
    return _b64url(digest)

def _make_disclosure(salt: str, claim_name: str, claim_value) -> str:
    """Encode a single disclosure as base64url([salt, claim_name, claim_value])."""
    raw = json.dumps([salt, claim_name, claim_value], separators=(',', ':'))
    return _b64url(raw.encode())

def _sign(private_key, data: str) -> str:
    """Sign data with ECDSA P-256 and return base64url signature."""
    signature = private_key.sign(data.encode(), ec.ECDSA(hashes.SHA256()))
    return _b64url(signature)

def create_sd_jwt(
    claims: dict,
    issuer_private_key,
    issuer_id: str,
    holder_public_key_pem: str,
    credential_type: str,
) -> dict:
    """
    Create an SD-JWT bundle.
    
    Each claim gets individually salted and hashed.
    The issuer signs over all the hashes.
    Returns a bundle with the JWT and all disclosures.
    """

    # 1. Build disclosures for each claim
    disclosures = {}
    sd_hashes = []

    # These claims go into the JWT directly, not as selective disclosures
    protected_claims = {"jti", "credential_type"}

    for key, value in claims.items():
        if key in protected_claims:
            continue
        salt = _b64url(uuid.uuid4().bytes)
        disclosure = _make_disclosure(salt, key, value)
        digest = _hash_disclosure(disclosure)
        disclosures[key] = disclosure
        sd_hashes.append(digest)

    # 2. Build JWT payload
    payload = {
        "iss": issuer_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + 365 * 24 * 3600,  # 1 year validity
        "jti": claims.get("jti"),
        "credential_type": credential_type,
        "_sd": sd_hashes,
        "_sd_alg": "sha-256",
        "cnf": {
            "jwk": holder_public_key_pem.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        }
    }

    # 3. Build header
    header = {
        "alg": "ES256",
        "typ": "sd-jwt"
    }

    # 4. Sign the JWT
    header_b64  = _b64url(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = _b64url(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = _sign(issuer_private_key, signing_input)

    jwt = f"{signing_input}.{signature}"

    # 5. Return the full bundle
    return {
        "jwt": jwt,
        "disclosures": disclosures,
        "credential_type": credential_type,
    }

def verify_sd_jwt(jwt_token: str, issuer_public_key) -> bool:
    """
    Verify the issuer's ECDSA P-256 signature over the JWT.
    Returns True if valid, False if tampered
    """
    try:
        parts = jwt_token.split(".")
        if len(parts) != 3:
            return False

        header_64, payload_64, signature_64 = parts
        signing_input = f"{header_64}.{payload_64}"

        # Decode the signature
        padded = signature_64 + "=" * (4 - len(signature_64) % 4)
        signature_bytes = base64.urlsafe_b64decode(padded)

        # Verify
        issuer_public_key.verify(
            signature_bytes,
            signing_input.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False

def verify_holder_binding(jwt_token: str, holder_public_key: str) -> bool:
    """
    Verify that the credential was issued to this specific device.
    This is an anti cloning check
    """
    try:
        payload_64 = jwt_token.split(".")[1]
        padded = payload_64 + "=" * (4 - len(payload_64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())

        cnf_key = payload.get("cnf", {}).get("jwk", "").strip()
        return cnf_key == holder_public_key.strip()

    except Exception:
        return False
