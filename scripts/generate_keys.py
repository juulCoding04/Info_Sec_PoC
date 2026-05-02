import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from crypto.keys import generate_keypair, save_keypair

parties = [
    "issuer/issuer_keys/ugent",
    "issuer/issuer_keys/belgian_government",
    "wallet/device_keys"
]

for dir in parties:
    if os.path.exists(f"{dir}/private_key.pem"):
        print(f"Keys already exist for {dir}, skipping.")
        continue

    priv, pub = generate_keypair()
    save_keypair(priv, pub, dir)
    print(f"Keys have been saved to {dir}")

