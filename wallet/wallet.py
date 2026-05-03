import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# --- Directories ---
BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
STORAGE_DIR = os.path.join(os.path.dirname(__file__), 'storage', 'credentials')
REVOCATION_FILE = os.path.join(BASE_DIR, 'data', 'revocation_list.json')
ISSUERS_FILE = os.path.join(BASE_DIR, 'data', 'trusted_issuers.json')
INCOMING_DIR = os.path.join(BASE_DIR, 'data', 'issued_credentials')
PRESENTATION_DIR = os.path.join(BASE_DIR, 'data', 'presentations')

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
    pass

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
