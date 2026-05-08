import sys
import os
import json
import base64
import hashlib
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.keys import load_public_key, generate_keypair, save_keypair
from crypto.signing import verify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
PRESENTATION_DIR = os.path.join(BASE_DIR, 'data', 'presentations')
REVOCATION_FILE = os.path.join(BASE_DIR, 'data', 'revocation_list.json')
ISSUERS_FILE = os.path.join(BASE_DIR, 'data', 'trusted_issuers.json')
DEVICE_PUBLIC_KEY_PATH = os.path.join(BASE_DIR, 'wallet', 'device_keys', 'public_key.pem')
VERIFIER_KEY_DIR = os.path.join(os.path.dirname(__file__), 'verifier_keys')


def _info(msg): print(f"[INFO]  {msg}")
def _warn(msg): print(f"[WARN]  {msg}")
def _ok(msg):   print(f"[OK]    {msg}")
def _err(msg):  print(f"[ERR]   {msg}")
def die(msg):
    _err(msg)
    sys.exit(1)


# --- SD-JWT helpers ---

def _b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def decode_disclosure(disclosure: str) -> tuple[str, object]:
    """Decode a SD-JWT disclosure string → (claim_name, claim_value)."""
    raw = _b64url_decode(disclosure)
    parts = json.loads(raw)
    _, claim_name, claim_value = parts
    return claim_name, claim_value

def hash_disclosure(disclosure: str) -> str:
    """SHA-256 hash of a disclosure string, base64url-encoded (no padding)."""
    digest = hashlib.sha256(disclosure.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


# --- Revocation / trust checks ---

def is_revoked(jti: str) -> bool:
    if not jti or not os.path.exists(REVOCATION_FILE):
        return False
    with open(REVOCATION_FILE) as f:
        data = json.load(f)
    return jti in data.get("revoked_ids", [])

def get_trusted_issuer(issuer_name: str) -> dict | None:
    if not os.path.exists(ISSUERS_FILE):
        return None
    with open(ISSUERS_FILE) as f:
        registry = json.load(f)
    for entry in registry["trusted_issuers"]:
        if entry["name"] == issuer_name:
            return entry
    return None


# --- JWT verification ---

def verify_sd_jwt_signature(jwt_str: str, issuer_public_key) -> dict | None:
    """
    Verify the issuer's ECDSA signature on the SD-JWT.
    Returns the decoded payload dict on success, None on failure.
    """
    try:
        parts = jwt_str.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig_bytes = _b64url_decode(sig_b64)
        issuer_public_key.verify(sig_bytes, signing_input, ec.ECDSA(hashes.SHA256()))
        return json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None


# --- Commands ---

def cmd_init(args):
    if os.path.exists(os.path.join(VERIFIER_KEY_DIR, 'private_key.pem')) and not args.force:
        _warn("Keys already exist. Use --force to overwrite.")
        return
    private_key, public_key = generate_keypair()
    save_keypair(private_key, public_key, VERIFIER_KEY_DIR)
    _ok("Verifier key pair generated.")
    _info(f"Keys saved to {VERIFIER_KEY_DIR}/")


def cmd_list(_args=None):
    os.makedirs(PRESENTATION_DIR, exist_ok=True)
    files = [f for f in os.listdir(PRESENTATION_DIR) if f.endswith('.json')]

    if not files:
        _info("No presentations found in data/presentations/")
        return

    print("\n" + "=" * 54)
    print("  Pending Presentations")
    print("=" * 54)
    for i, f in enumerate(files, 1):
        path = os.path.join(PRESENTATION_DIR, f)
        with open(path) as fh:
            p = json.load(fh)
        ctype = p.get("credential_type", "unknown")
        issuer = p.get("issuer") or "unknown"
        jti = p.get("jti") or "—"
        print(f"  [{i}] {f}")
        print(f"       type={ctype}  issuer={issuer}  jti={jti}")
    print("=" * 54)


def cmd_verify(args):
    path = args.presentation
    if not os.path.isabs(path):
        path = os.path.join(PRESENTATION_DIR, path)

    if not os.path.exists(path):
        die(f"Presentation file not found: {path}")

    with open(path) as f:
        presentation = json.load(f)

    print("\n" + "═" * 54)
    print("  Verifying Presentation")
    print("═" * 54)
    print(f"  File:            {os.path.basename(path)}")
    print(f"  Credential type: {presentation.get('credential_type', '—')}")
    print(f"  Issuer:          {presentation.get('issuer') or '—'}")
    print(f"  JTI:             {presentation.get('jti') or '—'}")
    print(f"  Nonce:           {presentation.get('nonce', '—')}")
    print("═" * 54)

    passed = True

    # 1. Device signature
    print("\n[1] Device signature ... ", end="", flush=True)
    if not os.path.exists(DEVICE_PUBLIC_KEY_PATH):
        print("SKIP")
        _warn("Wallet device public key not found — cannot verify device binding.")
    else:
        device_pub = load_public_key(DEVICE_PUBLIC_KEY_PATH)
        presentation_data = {k: v for k, v in presentation.items()
                             if k not in ("device_sig", "issuer_sig")}
        device_sig = presentation.get("device_sig")
        if not device_sig:
            print("FAIL")
            _warn("No device signature found in presentation.")
            passed = False
        elif verify(presentation_data, device_sig, device_pub):
            print("OK")
        else:
            print("FAIL")
            _err("Device signature is invalid — presentation may have been tampered with.")
            passed = False

    # 2. Revocation check
    print("\n[2] Revocation check ... ", end="", flush=True)
    jti = presentation.get("jti")
    if not jti:
        print("SKIP")
        _warn("No JTI in presentation — cannot check revocation list.")
    elif is_revoked(jti):
        print("REVOKED")
        _err(f"Credential '{jti}' is revoked.")
        passed = False
    else:
        print("OK")

    # 3. Trusted issuer
    print("\n[3] Trusted issuer ... ", end="", flush=True)
    issuer_name = presentation.get("issuer")
    issuer_entry = None
    if not issuer_name:
        print("SKIP")
        _warn("No issuer name in presentation — cannot check trust registry.")
    else:
        issuer_entry = get_trusted_issuer(issuer_name)
        if issuer_entry is None:
            print("FAIL")
            _err(f"Issuer '{issuer_name}' is NOT in the trusted issuers registry.")
            passed = False
        else:
            print("OK")

    # 4. SD-JWT issuer signature
    print("\n[4] Issuer SD-JWT signature ... ", end="", flush=True)
    issuer_sig = presentation.get("issuer_sig")
    if not issuer_sig:
        print("SKIP")
        _warn("No SD-JWT (issuer_sig) in presentation — issuer signature not verified.")
    elif issuer_entry is None:
        print("SKIP")
        _warn("Cannot verify SD-JWT without a trusted issuer entry.")
    else:
        pub_key_path = os.path.join(BASE_DIR, issuer_entry["public_key_path"])
        if not os.path.exists(pub_key_path):
            print("SKIP")
            _warn(f"Issuer public key not found at {pub_key_path}.")
        else:
            issuer_pub = load_public_key(pub_key_path)
            jwt_payload = verify_sd_jwt_signature(issuer_sig, issuer_pub)
            if jwt_payload is None:
                print("FAIL")
                _err("Issuer SD-JWT signature is invalid.")
                passed = False
            else:
                print("OK")
                # 4a. Verify disclosed claims are committed in JWT
                sd_hashes = set(jwt_payload.get("_sd", []))
                disclosed = presentation.get("disclosed_claims", {})
                all_bound = True
                for disc_str in disclosed.values():
                    if hash_disclosure(disc_str) not in sd_hashes:
                        _err(f"Disclosure not committed in SD-JWT: {disc_str[:32]}...")
                        all_bound = False
                        passed = False
                if all_bound:
                    _ok("All disclosed claims are committed in the SD-JWT.")

                # 4b. Expiry
                import time
                exp = jwt_payload.get("exp")
                if exp and int(time.time()) > exp:
                    _warn("Credential has expired.")
                    passed = False

    # 5. Decode and display disclosed claims
    print("\n" + "═" * 54)
    print("  Disclosed Claims")
    print("═" * 54)
    disclosed = presentation.get("disclosed_claims", {})
    if not disclosed:
        _warn("No claims disclosed in this presentation.")
    else:
        for key, disc_str in disclosed.items():
            try:
                claim_name, claim_value = decode_disclosure(disc_str)
                print(f"  {claim_name}: {claim_value}")
            except Exception:
                _warn(f"Could not decode disclosure for key '{key}': {disc_str[:32]}...")

    # 6. Final verdict
    print("\n" + "═" * 54)
    if passed:
        _ok("Presentation ACCEPTED — all checks passed.")
    else:
        _err("Presentation REJECTED — one or more checks failed.")
    print("═" * 54)


# --- CLI ---

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifier",
        description="Identity Wallet PoC — Verifier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m verifier.verifier init
  python -m verifier.verifier list
  python -m verifier.verifier verify --presentation presentation_abc123.json
        """,
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    p_init = sub.add_parser("init", help="Generate verifier key pair (run once)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing keys")

    sub.add_parser("list", help="List pending presentations in data/presentations/")

    p_verify = sub.add_parser("verify", help="Verify a presentation")
    p_verify.add_argument(
        "--presentation", "-p",
        required=True,
        metavar="FILE",
        help="Filename or full path to the presentation JSON",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "init":
        cmd_init(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "verify":
        cmd_verify(args)


if __name__ == "__main__":
    main()
