import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.keys import load_private_key
from crypto.signing import sign

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

# --- Helpers ---
def is_revoked(jti: bool) -> bool:
    if not os.path.exists(REVOCATION_FILE):
        return False
    with open(REVOCATION_FILE) as f:
        data = json.load(f)
    return jti in data.get("revoked_ids", [])

def is_trusted_issuer(issuer_name: str, issuer_pub_key: str) -> bool:
    """
    Check if an issuer is in the trusted registry. This function checks both name and public key so a malicious party cannot impersonate a trusted issuer by name alone.
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
    print("\n[TEE OPERATION] Biometric confirmation required.")
    input("Press ENTER to confirm presence (simulates fingerprint scan): ")
    print("User presence verified\n")

# --- Commands ---
def list_credentials():
    """
    Shows all credentials stored in wallet/storage/
    """
    os.makedirs(STORAGE_DIR, exist_ok=True)
    # store all files with .json extension in a list
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

        status = "!!! Revoked !!!" if is_revoked(cred.get("jti", "")) else "VALID"
        cred_type = cred.get("credential_type", "unknown")
        issuer = cred.get("issuer", "unknown")
        print(f"[{i}] {cred_type} - {issuer} {status}")
    print("")

def receive_credentials():
    """
    Pick up pending credentials from data/issued_credentials/
    """
    os.makedirs(INCOMING_DIR, exist_ok=True)
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

    # Display all claims before user accepts
    print("\n" + "=" * 40)
    print("Credential details")
    print("=" * 40)

    print(f"Issuer:     {cred.get('issuer', 'unknown')}")
    print(f"Type:       {cred.get('credential_type', 'unknown')}")
    print(f"ID:         {cred.get('jti', 'unknown')}")
    print("\nAll Claims contained in this credential:")

    disclosures = cred.get("disclosures", {})
    for key, value in disclosures.items():
        print(f"{key}: {value}")

    print("=" * 40)

    # Check if issuer is trusted before asking user to confirm
    issuer_name = cred.get("issuer", "")
    issuer_pub_key = f"issuer/issuer_keys/{issuer_name.lower()}/public_key.pem"

    if not os.path.exists(issuer_pub_key):
        _warn("Public key file not found")
    with open(issuer_pub_key, "rb") as f:
        issuer_pub_key_pem = f.read().decode()

    if not is_trusted_issuer(issuer_name, issuer_pub_key_pem):
        _warn(f"Issuer {issuer_name}, is NOT a trusted issuer")
        _warn(f"Accepting this credential may be risky")

    _ok("Issuer is trusted")

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

    print("\n"+"=" * 40)
    print("Select Credential to present")
    print("=" * 40)

    valid_files = []
    for i, f in enumerate(files, 1):
        path = os.path.join(STORAGE_DIR, f)
        with open(path) as file:
            cred = json.load(file)

        jti = cred.get("jti", "")
        if is_revoked(jti):
            print(f"[{i}] {cred.get('credential_type')} revoked - cannot present")
        else:
            print(f"[{i}] {cred.get('credential_type')} valid")
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

    disclosures = credential.get("disclosures", {})
    claim_keys = list(disclosures.keys())

    for i, key in enumerate(claim_keys, 1):
        print(f"[{i}] {key}: {disclosures[key]}")
    print("\n Enter claim numbers to disclose (comma separated e.g. 1,2,3)")
    choices = input("> ").strip().split(",")

    try:
        selected_claims = {
            claim_keys[int(c.strip()) - 1]: disclosures[claim_keys[int(c.strip()) - 1]]
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
    for key in disclosures:
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
    # TODO: verifier must send this
    nonce = input("Enter nonce from verifier (or press ENTER for demo): ").strip()
    if not nonce:
        import secrets
        nonce = secrets.token_hex(16)
        _info(f"Using demo nonce: {nonce}")

    # Build presentation
    # [TEE OPERATION]
    private_key = load_private_key(os.path.join(DEVICE_KEY_DIR, 'private_key.pem'))

    presentation_data = {
        "disclosed_claims": selected_claims,
        "nonce": nonce,
        "issuer": credential.get("issuer"),
        "credential_type": credential.get("credential_type"),
        "jti": credential.get("jti")
    }

    signature = sign(presentation_data, private_key)

    presentation = {
        **presentation_data,
        "device_sig": signature,
        "issuer_sig": credential.get("issuer_signature"),
    }

    # Save to data/presentations/
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
