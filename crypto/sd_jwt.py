import json
import uuid
import base64
import hashlib
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
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
            "jwk": holder_public_key_pem  # device binding
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