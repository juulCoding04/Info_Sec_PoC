import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.sd_jwt import verify_holder_binding, verify_sd_jwt
from wallet.sd_utils import get_jwt_payload, verify_disclosures
from wallet.directories import REVOCATION_FILE, ISSUERS_FILE, STORAGE_DIR

def is_expired(cred: dict) -> bool:
    payload = get_jwt_payload(cred)
    exp = payload.get("exp")
    if exp is None:
        return False
    return time.time() > exp

def is_revoked(cred: dict) -> bool:
    # [NETWORK OPERATION]
    # In real life the wallet would query the issuer's revocation service
    # In this PoC we simulate this using a JSON file
    payload = get_jwt_payload(cred)
    jti = payload.get("jti", "")

    if not os.path.exists(REVOCATION_FILE):
        return False
    with open(REVOCATION_FILE) as f:
        data = json.load(f)
    return jti in data.get("revoked_ids", [])

def is_trusted_issuer(cred: dict) -> bool:
    """
    Check if an issuer is in the trusted registry. This function checks both name and public key so a malicious party cannot impersonate a trusted issuer by name alone.
    
    [NETWORK OPERATION]
    In real life the wallet would check this against a national Trusted List, in this PoC we mock this using a JSON file
    """
    payload = get_jwt_payload(cred)
    issuer_name = payload.get("iss", "unknown")

    issuer_pub_key_pem = cred.get("issuer_public_key", "")
    if not issuer_pub_key_pem:
        return False

    if not os.path.exists(ISSUERS_FILE):
        return False

    with open(ISSUERS_FILE) as file:
        registry = json.load(file)

    for issuer in registry["trusted_issuers"]:
        if issuer["name"] == issuer_name:
            key_path = issuer["public_key_path"]
            if not os.path.exists(key_path):
                return False
            with open(key_path, "rb") as f:
                registered_pem = f.read().decode()

            return registered_pem.strip() == issuer_pub_key_pem.strip()

    return False

def is_duplicate_credential(cred: dict) -> bool:
    """
    Check wether a credential with the same jti is already stored in the wallet
    """
    incoming_payload = get_jwt_payload(cred)
    incoming_jti = incoming_payload.get("jti")

    if not incoming_jti:
        return False

    files = [f for f in os.listdir(STORAGE_DIR) if f.endswith(".json")]

    for filename in files: 
        path = os.path.join(STORAGE_DIR, filename)

        try:
            with open(path) as f:
                stored_cred = json.load(f)

            stored_payload = get_jwt_payload(stored_cred)
            stored_jti = stored_payload.get("jti")

            if stored_jti == incoming_jti:
                return True

        except Exception:
            continue

    return False

def verify_credentials(cred, issuer_key, device_key):
    if is_duplicate_credential(cred):
        return False, "Credential already exists inside the wallet"

    if not verify_sd_jwt(cred["jwt"], issuer_key):
        return False, "Invalid issuer signature"

    if not is_trusted_issuer(cred):
        return False, "Issuer is not trusted"

    if not verify_holder_binding(cred["jwt"], device_key):
        return False, "Invalid holder binding"

    if not verify_disclosures(cred):
        return False, "Tampered disclosures"

    if is_expired(cred):
        return False, "Credential expired"

    if is_revoked(cred):
        return False, "Credential revoked"

    return True, "Credential valid"

