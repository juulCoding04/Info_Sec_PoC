from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import os

# generate keypair
def generate_keypair():
    """
    Generating ECDSA P-256 key pair.
    In a real system this would happen inside the TEE/SE
    """
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()

    print("ECDSA key pair generated succesfully.")

    return private_key, public_key

# save keypair
def save_keypair(private_key, public_key, dir):
    """
    Save key pair as PEM files.
    Simulate TEE-bound key storage
    """
    os.makedirs(dir, exist_ok=True)

    # Serialize private key to PEM
    pem_priv_key = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    # Serialize public key to PEM
    pem_pub_key = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    # Save keys in dir
    with open(f"{dir}/private_key.pem", "wb") as f:
        f.write(pem_priv_key)

    with open(f"{dir}/public_key.pem", "wb") as f:
        f.write(pem_pub_key)

    print(f"Keys saved to {dir}/")

# load private key
def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# load public key
def load_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())
def key_exists(key_id: str) -> bool:
    dir = os.path.join(os.path.dirname(__file__), '..', 'issuer', 'issuer_keys', key_id)
    return os.path.exists(os.path.join(dir, 'private_key.pem'))

def get_public_key_pem(key_id: str) -> str:
    path = os.path.join(os.path.dirname(__file__), '..', 'issuer', 'issuer_keys', key_id, 'public_key.pem')
    with open(path, 'r') as f:
        return f.read()

def generate_key_pair(key_id: str):
    dir = os.path.join(os.path.dirname(__file__), '..', 'issuer', 'issuer_keys', key_id)
    priv, pub = generate_keypair()
    save_keypair(priv, pub, dir)

def load_private_key_by_id(key_id: str):
    path = os.path.join(os.path.dirname(__file__), '..', 'issuer', 'issuer_keys', key_id, 'private_key.pem')
    return load_private_key(path)