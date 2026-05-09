import sys
import os
import json
import base64
import hashlib
import time
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from crypto.keys import load_public_key, generate_keypair, save_keypair
from crypto.signing import verify
from crypto.sd_jwt import verify_sd_jwt

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


# --- JWT / SD-JWT helpers ---

def _b64url_decode(s: str) -> bytes:
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _parse_jwt_payload(jwt_str: str) -> dict | None:
    """Decode the JWT payload without verifying the signature."""
    try:
        parts = jwt_str.split('.')
        if len(parts) != 3:
            return None
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None

def decode_disclosure(disclosure: str) -> tuple[str, object]:
    """Decode a SD-JWT disclosure string → (claim_name, claim_value)."""
    raw = _b64url_decode(disclosure)
    _, claim_name, claim_value = json.loads(raw)
    return claim_name, claim_value

def _hash_disclosure(disclosure: str) -> str:
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
        payload = _parse_jwt_payload(p.get("issuer_jwt", "")) or {}
        ctype = payload.get("credential_type", "unknown")
        issuer = payload.get("iss") or "unknown"
        jti = payload.get("jti") or "—"
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

    issuer_jwt = presentation.get("issuer_jwt")
    disclosures = presentation.get("disclosures", [])
    nonce = presentation.get("nonce")
    device_sig = presentation.get("device_sig")

    # Parse JWT payload early (unverified) for display and lookups
    raw_payload = _parse_jwt_payload(issuer_jwt) if issuer_jwt else {}
    issuer_name = (raw_payload or {}).get("iss")
    jti = (raw_payload or {}).get("jti")
    credential_type = (raw_payload or {}).get("credential_type")

    print("\n" + "═" * 54)
    print("  Verifying Presentation")
    print("═" * 54)
    print(f"  File:            {os.path.basename(path)}")
    print(f"  Credential type: {credential_type or '—'}")
    print(f"  Issuer:          {issuer_name or '—'}")
    print(f"  JTI:             {jti or '—'}")
    print(f"  Nonce:           {nonce or '—'}")
    print("═" * 54)

    passed = True

    # 1. Device signature — signed over {issuer_jwt, disclosures, nonce}
    print("\n[1] Device signature ... ", end="", flush=True)
    if not os.path.exists(DEVICE_PUBLIC_KEY_PATH):
        print("SKIP")
        _warn("Wallet device public key not found — cannot verify device binding.")
    else:
        device_pub = load_public_key(DEVICE_PUBLIC_KEY_PATH)
        signed_data = {k: v for k, v in presentation.items() if k != "device_sig"}
        if not device_sig:
            print("FAIL")
            _warn("No device signature found in presentation.")
            passed = False
        elif verify(signed_data, device_sig, device_pub):
            print("OK")
        else:
            print("FAIL")
            _err("Device signature is invalid — presentation may have been tampered with.")
            passed = False

    # 2. Nonce check
    print("\n[2] Nonce present ... ", end="", flush=True)
    if not nonce:
        print("FAIL")
        _err("No nonce in presentation — replay attacks cannot be detected.")
        passed = False
    else:
        print("OK")
        _info("(In production the verifier would match this against its own issued nonce.)")

    # 3. Trusted issuer
    print("\n[3] Trusted issuer ... ", end="", flush=True)
    issuer_entry = None
    if not issuer_name:
        print("SKIP")
        _warn("No issuer (iss) in JWT payload — cannot check trust registry.")
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
    jwt_payload = None
    if not issuer_jwt:
        print("SKIP")
        _warn("No issuer_jwt in presentation.")
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
            # verify_sd_jwt returns True/False; decode payload separately
            if not verify_sd_jwt(issuer_jwt, issuer_pub):
                print("FAIL")
                _err("Issuer SD-JWT signature is invalid.")
                passed = False
            else:
                jwt_payload = raw_payload  # signature verified — payload is trustworthy
                print("OK")

                exp = jwt_payload.get("exp")
                if exp and int(time.time()) > exp:
                    _warn("Credential has expired.")
                    passed = False

    # 5. Disclosure integrity — every disclosure must be committed in the JWT's _sd
    print("\n[5] Disclosure integrity ... ", end="", flush=True)
    if jwt_payload is None:
        print("SKIP")
        _warn("Cannot check disclosures without a verified JWT payload.")
    elif not disclosures:
        print("SKIP")
        _warn("No disclosures in presentation.")
    else:
        sd_hashes = set(jwt_payload.get("_sd", []))
        tampered = [disc for disc in disclosures
                    if _hash_disclosure(disc) not in sd_hashes]
        if tampered:
            print("FAIL")
            _err(f"Disclosures not committed in SD-JWT: {tampered}")
            passed = False
        else:
            print("OK")

    # 6. Revocation check
    print("\n[6] Revocation check ... ", end="", flush=True)
    if not jti:
        print("SKIP")
        _warn("No JTI in JWT payload — cannot check revocation list.")
    elif is_revoked(jti):
        print("REVOKED")
        _err(f"Credential '{jti}' is revoked.")
        passed = False
    else:
        print("OK")

    # 7. Decode and display disclosed claims
    print("\n" + "═" * 54)
    print("  Disclosed Claims")
    print("═" * 54)
    if not disclosures:
        _warn("No claims disclosed in this presentation.")
    else:
        for disc_str in disclosures:
            try:
                claim_name, claim_value = decode_disclosure(disc_str)
                print(f"  {claim_name}: {claim_value}")
            except Exception:
                _warn(f"Could not decode disclosure: {disc_str[:40]}...")

    # 8. Final verdict
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
