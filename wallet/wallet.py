import sys
import os
import json
import base64
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.keys import load_private_key, load_public_key
from crypto.signing import sign
from crypto.sd_jwt import verify_holder_binding, verify_sd_jwt

# --- Directories ---
BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'storage', 'credentials')
REVOCATION_FILE = os.path.join(BASE_DIR, 'data', 'revocation_list.json')
ISSUERS_FILE = os.path.join(BASE_DIR, 'data', 'trusted_issuers.json')
INCOMING_DIR = os.path.join(BASE_DIR, 'data', 'issued_credentials')
PRESENTATION_DIR = os.path.join(BASE_DIR, 'data', 'presentations')
DEVICE_KEY_DIR = os.path.join(os.path.dirname(__file__), 'device_keys')

# --- Messages ---
def _info(msg): print(f"\n[INFO]: {msg}")
def _warn(msg): print(f"\n[WARN]: {msg}")
def _ok(msg): print(f"\n[OK] {msg}")
def _err(msg): print(f"\n[ERR]: {msg}")

# --- Helper functions ---
def decode_disclosure(encoded: str) -> tuple:
    """
    decode a base64 SD-JWT disclosure
    Returns (claim_name, claim_value)
    """
    padded = encoded + "=" * (4 - len(encoded) % 4)
    decoded = base64.urlsafe_b64decode(padded).decode()
    parts = json.loads(decoded) # parts = [salt, key, value]

    return parts[1], parts[2]

def get_readable_disclosure(cred: dict) -> dict:
    readable = {}
    for key, enc in cred.get("disclosures", {}).items():
        try:
            claim_name, claim_value = decode_disclosure(enc)
            readable[claim_name] = claim_value
        except Exception:
            readable[key] = enc # fallback to raw encoded if decoding fails
    return readable

def get_jwt_payload(cred: dict) -> dict:
    try:
        jwt = cred.get("jwt", "")
        payload_b64 = jwt.split(".")[1]
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode())
    except Exception:
        return {}

def is_expired(cred: dict) -> bool:
    payload = get_jwt_payload(cred)
    exp = payload.get("exp")
    if exp is None:
        return False
    return time.time() > exp

def is_revoked(jti: str) -> bool:
    # [NETWORK OPERATION]
    # In real life the wallet would query the issuer's revocation service
    # In this PoC we simulate this using a JSON file
    if not os.path.exists(REVOCATION_FILE):
        return False
    with open(REVOCATION_FILE) as f:
        data = json.load(f)
    return jti in data.get("revoked_ids", [])

def is_trusted_issuer(issuer_name: str, issuer_pub_key: str) -> bool:
    """
    Check if an issuer is in the trusted registry. This function checks both name and public key so a malicious party cannot impersonate a trusted issuer by name alone.
    
    [NETWORK OPERATION]
    In real life the wallet would check this against a national Trusted List, in this PoC we mock this using a JSON file
    """
    if not os.path.exists(ISSUERS_FILE):
        _warn("Trusted issuers list not found")
        return False

    with open(ISSUERS_FILE) as file:
        registry = json.load(file)

    for issuer in registry["trusted_issuers"]:
        if issuer["name"] == issuer_name:
            key_path = issuer["public_key_path"]
            if not os.path.exists(key_path):
                _warn(f"Public key file not found for {issuer_name}")
                return False
            with open(key_path, "rb") as f:
                registered_pem = f.read().decode()

            return registered_pem.strip() == issuer_pub_key.strip()

    return False

def simulate_user_presence():
    # [TEE OPERATION]
    # In real life this communication travels from biometric sensor to the TEE, bypassing the OS
    print("\n[TEE OPERATION] Biometric confirmation required.")
    input("Press ENTER to confirm presence (simulates fingerprint scan): ")
    print("User presence verified\n")

# --- Commands ---
def list_credentials():
    """
    Shows all credentials stored in wallet/storage/
    """
    os.makedirs(STORAGE_DIR, exist_ok=True)
    files = [f for f in os.listdir(STORAGE_DIR) if f.endswith('.json')]

    if not files:
        _info("No credentials stored!")
        return

    print("\n" + "=" * 40)
    print("Stored Credentials")
    print("=" * 40)

    for i, f in enumerate(files, 1):
        path = os.path.join(STORAGE_DIR, f)
        with open(path) as file:
            cred = json.load(file)

        payload = get_jwt_payload(cred)
        jti = payload.get("jti", "")
        if is_revoked(jti):
            status = "!!! REVOKED !!!"
        elif is_expired(cred):
            status = "!!! EXPIRED !!!"
        else:
            status = "VALID"
        cred_type = cred.get("credential_type", "unknown")
        issuer = payload.get("iss", "unknown")
        print(f"[{i}] {cred_type} - {issuer} {status}")
    print("")

def receive_credentials():
    """
    Pick up pending credentials from data/issued_credentials/
    """
    os.makedirs(INCOMING_DIR, exist_ok=True)
    # [NETWORK OPERATION]
    # In real life the issuer would deliver the credential directly to the wallet over a TLS connection
    # In this PoC this is simulated by reading data/issued_credentials/
    files = [f for f in os.listdir(INCOMING_DIR) if f.endswith('.json')]

    if not files:
        _info("No pending credentials")
        return

    print("\n" + "=" * 40)
    print("Pending Credentials")
    print("=" * 40)

    for i, f in enumerate(files, 1):
        print(f"[{i}] {f}")
    print("[0] Cancel")

    choice = input("\nSelect credential to import: ").strip()

    if choice == "0":
        _info("Pending credentials where not accepted")
        return

    try:
        selected = files[int(choice) - 1]
    except (ValueError, IndexError):
        _err("Invalid selection.")
        return

    path = os.path.join(INCOMING_DIR, selected)
    with open(path) as file:
        cred = json.load(file)

    # Extract metadata from JWT payload
    payload = get_jwt_payload(cred)
    issuer_name = payload.get("iss", "unknown")
    jti = payload.get("jti", "unknown")
    credential_type = cred.get("credential_type", "unknown")

    readable = get_readable_disclosure(cred)

    # Display all claims before user accepts
    print("\n" + "=" * 40)
    print("Credential details")
    print("=" * 40)

    print(f"Issuer:     {issuer_name}")
    print(f"Type:       {credential_type}")
    print(f"ID:         {jti}")
    print("\nAll Claims contained in this credential:")

    for key, value in readable.items():
        print(f"{key}: {value}")

    print("=" * 40)

    # Check if issuer is trusted before asking user to confirm
    # [NETWORK OPERATION]
    # In real life this queries the national Trusted List
    # In this PoC this reads from trusted_issuers.json
    issuer_pub_key_pem = cred.get("issuer_public_key", "")
    if not issuer_pub_key_pem:
        _warn("No issuer public key in credentials")
        return

    if not is_trusted_issuer(issuer_name, issuer_pub_key_pem):
        _warn(f"Issuer {issuer_name}, is NOT a trusted issuer")
        return
    else:
        _ok("Issuer is trusted")

    # Verify issuer signature
    with open(ISSUERS_FILE) as f:
        registry = json.load(f)

    issuer_pub_key_path = next(
        (i["public_key_path"] for i in registry["trusted_issuers"] if i["name"] == issuer_name), None
    )

    if not issuer_pub_key_path:
        _warn("Cannot find issuers public key path")
        return

    issuer_pub_key_obj = load_public_key(issuer_pub_key_path)

    if not verify_sd_jwt(cred["jwt"], issuer_pub_key_obj):
        _warn("Issuer signature verification FAILED. Credential may be tampered with")
        return

    _ok("Issuer signature verified")

    # Verify holder binding
    # [TEE OPERATION]
    # In real life the device key would be hardware boud.
    with open(os.path.join(DEVICE_KEY_DIR, "public_key.pem"), "r") as f:
        this_device_key = f.read()

    if not verify_holder_binding(cred["jwt"], this_device_key):
        _warn("Holder binding check FAILED. Credential was not issued to this device")
        return

    _ok("Holder binding verified")

    answer = input("\nAccept this credential? [y/N]: ").strip().lower()
    if answer != "y":
        _info("Credentials rejected")
        return

    # Store in wallet
    os.makedirs(STORAGE_DIR, exist_ok=True)
    dest = os.path.join(STORAGE_DIR, selected)
    with open(dest, "w") as f:
        json.dump(cred, f, indent=2)

    _ok("Credentials successfully stored in wallet!")

def present_credentials():
    """
    Select a credential and present it to a verifier
    """
    os.makedirs(STORAGE_DIR, exist_ok=True)
    files = [f for f in os.listdir(STORAGE_DIR) if f.endswith('.json')]

    if not files:
        _info("No credentials stored!")
        return

    print("\n"+"=" * 40)
    print("Select Credential to present")
    print("=" * 40)

    valid_files = []
    for i, f in enumerate(files, 1):
        path = os.path.join(STORAGE_DIR, f)
        with open(path) as file:
            cred = json.load(file)

        payload = get_jwt_payload(cred)
        jti = payload.get("jti", "")
        credential_type = cred.get("credential_type", "unknown")
        issuer = payload.get("iss", "unknown")

        if is_revoked(jti):
            print(f"[{i}] {credential_type} revoked - cannot present")
        elif is_expired(cred):
            print(f"[{i}] {credential_type} expired - cannot present")
        else:
            print(f"[{i}] {credential_type} valid")
            valid_files.append((i, f, cred))

    print("[0] Cancel")

    choice = input("\nSelect credential: ").strip()

    if choice == "0":
        _info("Presentation was canceled")
        return

    try:
        selected = next(
            (f, c) for i, f, c in valid_files if str(i) == choice
        )
    except StopIteration:
        _err("Invalid selection or credential revoked")
        return

    filename, credential = selected

    # Show what will be disclosed.
    # In a real system the verifier specifies what it needs
    # Here we let the user choose for demo purposes
    print("\n" + "=" * 40)
    print("Select claims to disclose")
    print("=" * 40)
    print("(In a real system the verifier specifies this)")

    readable_disc = get_readable_disclosure(credential)
    claim_keys = list(readable_disc.keys())

    for i, key in enumerate(claim_keys, 1):
        print(f"[{i}] {key}: {readable_disc[key]}")
    print("\n Enter claim numbers to disclose (comma separated e.g. 1,2,3)")
    choices = input("> ").strip().split(",")

    try:
        selected_claims = {
            claim_keys[int(c.strip()) - 1]: readable_disc[claim_keys[int(c.strip()) - 1]]
            for c in choices
        }
    except (ValueError, IndexError):
        _err("Invalid selection")
        return
    
    # Show consent summary
    print("\n" + "=" * 40)
    print("Consent summary")
    print("=" * 40)
    print("You are about to share:")
    for key, value in selected_claims.items():
        print(f"{key}: {value}")
    print("The follwing will NOT be shared")
    for key in readable_disc:
        if key not in selected_claims:
            print(f"{key}")

    print("=" * 40)

    answer = input("\nConfirm presentation [y/N]: ").strip().lower()
    if answer != "y":
        _info("Presentation was cancelled")
        return

    # Simulate biometric confirmation here
    # [TEE OPERATION]
    simulate_user_presence()

    # Get nonce from verifier
    # [NETWORK OPERATION]
    # In real life the verifier sends a fresh random nonce with every presentation.
    # In this PoC we ask the user to manually enter the nonce
    # TODO: verifier must send this
    nonce = input("Enter nonce from verifier (or press ENTER for demo): ").strip()
    if not nonce:
        import secrets
        nonce = secrets.token_hex(16)
        _info(f"Using demo nonce: {nonce}")

    # Build presentation
    # [TEE OPERATION]
    # In real life this siging operation happens inside the TEE
    private_key = load_private_key(os.path.join(DEVICE_KEY_DIR, 'private_key.pem'))

    payload = get_jwt_payload(credential)
    presentation_data = {
        "disclosed_claims": selected_claims,
        "nonce": nonce,
        "issuer": payload.get("iss"),
        "credential_type": credential.get("credential_type"),
        "jti": payload.get("jti")
    }

    signature = sign(presentation_data, private_key)

    presentation = {
        **presentation_data,
        "device_sig": signature,
        "issuer_jwt": credential.get("jwt")
    }

    # [NETWORK OPERATION]
    # In real life the wallet sent directly to the verifier
    # In this PoC this is simulated by saving to data/presentations/
    os.makedirs(PRESENTATION_DIR, exist_ok=True)
    import uuid
    out_path = os.path.join(PRESENTATION_DIR, f"presentation_{uuid.uuid4().hex[:8]}.json")
    with open(out_path, "w") as f:
        json.dump(presentation, f, indent=2)

    _ok("Presentation created and sent to verifier")
    _info(f"Output: {out_path}")

# --- Main menu ---
def main_menu():
    print("\n" + "=" * 40)
    print("Digital Identity Wallet")
    print("=" * 40)

    while True:
        print("\n" + "=" * 40)
        print("MAIN MENU")
        print("=" * 40)
        print("\n[1] View stored credentials")
        print("[2] Receive new credentials")
        print("[3] Present credentials")
        print("[q] Quit")

        choice = input("\nChoose an option: ").strip().lower()

        if choice == "1":
            list_credentials()
        elif choice == "2":
            receive_credentials()
        elif choice == "3":
            present_credentials()
        elif choice == "q":
            print("\nQuiting...")
            break
        else:
            _err("Invalid option.")

if __name__ == "__main__":
    main_menu()
