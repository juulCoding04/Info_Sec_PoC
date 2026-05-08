import sys
import os
import json
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.keys import load_private_key, load_public_key
from crypto.signing import sign

from wallet.sd_utils import get_jwt_payload, get_readable_disclosure
from wallet.validation import verify_credentials, is_revoked, is_expired
from wallet.directories import PIN_FILE, STORAGE_DIR, INCOMING_DIR, DEVICE_KEY_DIR, ISSUERS_FILE, PRESENTATION_DIR
from wallet.messages import _info, _warn, _err, _ok
from wallet.auth import simulate_user_presence, setup_pin

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

        if is_revoked(cred):
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

    # Verify credentials
    issuer_pub_key_pem = cred.get("issuer_public_key", "")
    if not issuer_pub_key_pem:
        _warn("No issuer public key in credentials")
        return

    with open(os.path.join(DEVICE_KEY_DIR, "public_key.pem"), "r") as f:
        this_device_key = f.read()

    with open(ISSUERS_FILE) as f:
        registry = json.load(f)

    issuer_pub_key_path = next(
        (i["public_key_path"] for i in registry["trusted_issuers"] if i["name"] == issuer_name), None
    )

    if not issuer_pub_key_path:
        _warn("Cannot find issuers public key path")
        return

    issuer_pub_key_obj = load_public_key(issuer_pub_key_path)

    verify, msg = verify_credentials(cred, issuer_pub_key_obj, this_device_key)
    if not verify:
        _warn(msg)
        return
    _ok(msg)

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

    answer = input("\nAccept this credential? [y/N]: ").strip().lower()
    if answer != "y":
        _info("Credentials rejected")
        return

    # Store in wallet
    # (move from data/issued_credentials to wallet/storage)
    os.makedirs(STORAGE_DIR, exist_ok=True)
    dest = os.path.join(STORAGE_DIR, selected)

    shutil.move(path, dest)

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

    _, credential = selected

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
        all_disclosures = credential.get("disclosures", {})
        selected_disclosures = []
        selected_readable = {}

        for c in choices:
            idx = int(c.strip()) - 1
            claim_name = claim_keys[idx]
            encoded_disclosure = all_disclosures[claim_name]
            selected_disclosures.append(encoded_disclosure)
            selected_readable[claim_name] = readable_disc[claim_name]
    except (ValueError, IndexError):
        _err("Invalid selection")
        return
    
    # Show consent summary
    print("\n" + "=" * 40)
    print("Consent summary")
    print("=" * 40)
    print("You are about to share:")
    for key, value in selected_readable.items():
        print(f"{key}: {value}")
    print("The follwing will NOT be shared")
    for key in readable_disc:
        if key not in selected_readable:
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
    nonce = input("Enter nonce from verifier (or press ENTER for demo): ").strip()
    if not nonce:
        import secrets
        nonce = secrets.token_hex(16)
        _info(f"Using demo nonce: {nonce}")

    # Build presentation
    # [TEE OPERATION]
    # In real life this siging operation happens inside the TEE
    private_key = load_private_key(os.path.join(DEVICE_KEY_DIR, 'private_key.pem'))

    presentation_data = {
        "issuer_jwt": credential.get("jwt"),
        "disclosures": selected_disclosures,
        "nonce": nonce
    }

    signature = sign(presentation_data, private_key)

    presentation = {
        **presentation_data,
        "device_sig": signature,
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
    # First time - setup
    if not os.path.exists(PIN_FILE):
        print("\nWelcome to the Identity Wallet!")
        print("This is your first time running the application")
        setup_pin()
        # Generate device keys on first run
        if not os.path.exists(os.path.join(DEVICE_KEY_DIR, 'private_key.pem')):
            from crypto.keys import generate_keypair, save_keypair

            priv, pub = generate_keypair()
            save_keypair(priv, pub, DEVICE_KEY_DIR)
            _info("Device keys generated")
    main_menu()
