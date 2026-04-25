import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from crypto.keys import generate_keypair, save_keypair, load_private_key, load_public_key

def test_key_gen_and_load():
    priv, pub = generate_keypair()
    save_keypair(priv, pub, 'test/test_keys')

    loaded_priv_key = load_private_key('test/test_keys/private_key.pem')
    print(f"private key: {loaded_priv_key}")
    loaded_pub_key = load_public_key('test/test_keys/public_key.pem')
    print(f"public key: {loaded_pub_key}")

    print("Keys generated and loaded succesfully")

if __name__ == "__main__":
    test_key_gen_and_load()
