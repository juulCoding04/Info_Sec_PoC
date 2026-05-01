# run this once as: python generate_holder_keys.py
import sys, os
sys.path.insert(0, '.')
from crypto.keys import generate_keypair, save_keypair

priv, pub = generate_keypair()
save_keypair(priv, pub, "keys/holder_device")
print("Holder device keys generated.")