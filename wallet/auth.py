import sys
import os
import json
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from wallet.messages import _err, _ok, _warn
from wallet.directories import PIN_FILE

def hash_pin(pin: str) -> str:
    """
    Hash PIN with SHA-256 for storage
    """
    return hashlib.sha256(pin.encode()).hexdigest()

def setup_pin():
    """
    First time setup -> user sets a wallet PIN

    [TEE OPERATION]
    In real life the PIN would be verified in the TEE and never leave the secure hardware.
    In this PoC we store it as a SHA256 hash
    """
    print("\n" + "=" * 40)
    print("Set wallet PIN")
    print("=" * 40)
    
    while True:
        pin = input("Enter pin (min 4 digits): ").strip()
        if len(pin) < 4 or not pin.isdigit():
            _err("PIN must be at least 4 digits")
            continue
        confirm = input("Confirm PIN: ").strip()
        if pin != confirm:
            _err("PINs don't match. Try again")
            continue
        break

    with open(PIN_FILE, "w") as f:
        json.dump({"pin_hash": hash_pin(pin)}, f)

    _ok("PIN set succesfully")

def unlock_wallet() -> bool:
    """
    Unlock wallet with PIN (or in real life biometric)

    [TEE OPERATION]

    After a max amount of tries the wallet would lock and require recovery
    """
    MAX_ATTEMPTS = 3

    with open(PIN_FILE) as f:
        stored = json.load(f)

    print("\n" + "="*40)
    print("Unlock wallet")
    print("=" * 40)

    for attempts in range(1, MAX_ATTEMPTS + 1):
        pin = input(f"Enter PIN (attempt {attempts}/{MAX_ATTEMPTS}): ").strip()
        if hash_pin(pin) == stored["pin_hash"]:
            _ok("Wallet unlocked")
            return True
        else:
            _err("Incorrect pin")

    _warn("Too many failed attempts. Wallet locked")
    _warn("In the real system this would trigger a recovery flow")
    return False

def simulate_user_presence():
    # [TEE OPERATION]
    # In real life this communication travels from biometric sensor to the TEE, bypassing the OS
    print("\n[TEE OPERATION] Biometric confirmation required.")
    input("Press ENTER to confirm presence (simulates fingerprint scan): ")
    print("User presence verified\n")

