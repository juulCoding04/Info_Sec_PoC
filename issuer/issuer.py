import argparse
import json
import os
import sys
import time
import uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto.keys import generate_keypair, save_keypair, load_private_key, load_public_key
from crypto.sd_jwt import create_sd_jwt


BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
DATA_DIR = os.path.join(BASE_DIR, "data")
TRUSTED_ISSUERS_FILE = os.path.join(DATA_DIR, "trusted_issuers.json")
REVOCATION_FILE = os.path.join(DATA_DIR, "revocation_list.json")


party_mapping = {
    "ugent" : "UGent",
    "BEgov" : "Belgian Government",
}

DATA : dict[str, dict] = {
    "student_id" : {
        "first_name" : "Alice",
        "last_name" : "Bobson",
        "date_of_birth" : "01/01/2004",
        "university" : "Ghent University",
        "faculty" : "Engineering and Architecture",
        "degree" : "Master of Science in Computer Science",
        "graduation_year" : None,
        "student_id" : "123456",
        "email" : "alice.bobson@ugent",
        "phone_number" : "123456789",
        "valid_until" : "30/09/2028"
    },
    "Diplomas": {
        "secondary_education" : {
            "school_name" : "High School of Ghent",
            "graduation_year" : "2024",
            "degree" : "Secondary Education Diploma",
            "field" : "Mathematics and Sciences",
        },
        "bachelor_degree" : {
            "university" : "Ghent University",
            "faculty" : "Engineering and Architecture",
            "degree" : "Bachelor of Science in Computer Science",
            "graduation_year" : "2026"
        },
    },
    "ID_card" : {
        "first_name" : "Alice",
        "last_name" : "Bobson",
        "date_of_birth" : "01/01/2004",
        "national_registration_number" : "12.34.56-789.01",
        "expiration_date" : "30/09/2034",
        "nationality" : "Belgian",
        "gender" : "Female",      
    },
    "driving_license" : {
        "first_name" : "Alice",
        "last_name" : "Bobson",
        "date_of_birth" : "01/01/2004",
        "license_number" : "1234567",
        "date_achieved" : "10/01/2022",
        "expiration_date" : "10/01/2032",
        "issuing_authority" : "Belgian Government",
        "categories" : ["AM", "B"]
    },
    "international_passport" : {
        "first_name" : "Alice",
        "last_name" : "Bobson",
        "date_of_birth" : "01/01/2004",
        "passport_number" : "123456789",
        "issue_date" : "01/01/2024",
        "expiration_date" : "01/01/2031",
        "nationality" : "Belgian",
        "gender" : "Female",
        "issuing_authority" : "Belgian Government",
    }
}

def load_issuers() -> dict:
    with(open(TRUSTED_ISSUERS_FILE, "r")) as f:
        return json.load(f)
    
def resolve_issuer_name(issuer):
    if issuer not in party_mapping:
        die(f"Error: Issuer '{issuer}' not found in party mapping.")
    
    party = party_mapping[issuer]
    issuers = load_issuers()
    entry = None
    issuers = issuers["trusted_issuers"]
    for e in issuers:
        if e["name"] == party:
            entry = e
            break
    
    if entry is None:
        die(f"Error: Issuer '{party}' not found in trusted issuers list.")
    
    return party, entry

def die(message):
    print(message)
    sys.exit(1)

def ok(message):
    print(f"OK: {message}")
    
def _info(msg: str):
    print(f"[INFO]  {msg}")


def _warn(msg: str):
    print(f"[WARN]  {msg}")

#def load_public_key(holder_key_id: str) -> str:
#    path = os.path.join(BASE_DIR, "keys", holder_key_id, "public_key.pem")
#    print(f"holder_key_id: {holder_key_id}")
#    if not os.path.exists(path):
#        die(f"Error: Public key for holder '{holder_key_id}' not found.")
#    with open(path) as f:
#        return f.read()
    
def save_credential(credential: dict, credential_type : str):
    os.makedirs(DATA_DIR, exist_ok=True)
    out = os.path.join(DATA_DIR, f"{credential_type.lower()}_credential.json")
    with open(out, "w") as f:
        json.dump(credential, f, indent=2)
    return out

def add_to_revocation_list(jti: str):
    with open(REVOCATION_FILE) as f:
        data = json.load(f)
    if jti not in data["revoked_ids"]:
        data["revoked_ids"].append(jti)
    with open(REVOCATION_FILE, "w") as f:
        json.dump(data, f, indent=2)

def cmd_init(party: str, entry: dict):
    key_id = entry["key_id"]
    dir = os.path.join(BASE_DIR,"issuer", 'issuer_keys', key_id)
    private_key_path = os.path.join(dir, 'private_key.pem')
    if os.path.exists(private_key_path):
        _warn(f"Keys already exist for '{party}'. Run with --force to overwrite.")
        _warn(f"No new keys generated. Exiting.")
        return
    private_key, public_key = generate_keypair()
    save_keypair(private_key, public_key, dir)
    ok(f"Key pair generated and saved for '{party}'.")
    _info(f"Public key stored at issuer/issuer_keys/{key_id}/public_key.pem (share with verifiers)")
    _info(f"Private key stored at issuer/issuer_keys/{key_id}/private_key.pem (keep secret)")


def cmd_init_force(party: str, entry: dict):
    _warn(f"Overwriting keys for '{party}'.")
    key_id  = entry["key_id"]
    dir = os.path.join(BASE_DIR,"issuer", 'issuer_keys', key_id)
    private_key, public_key = generate_keypair()
    save_keypair(private_key, public_key, dir)
    ok(f"Key pair generated and saved for '{party}'.")
    _info(f"Public key stored at issuer/issuer_keys/{key_id}/public_key.pem (share with verifiers)")
    _info(f"Private key stored at issuer/issuer_keys/{key_id}/private_key.pem (keep secret)")

def cmd_show_key(party: str, entry: dict):
    """Print this issuer's public key PEM."""
    key_id = entry["key_id"]
    path = os.path.join(BASE_DIR,"issuer", 'issuer_keys', key_id, 'public_key.pem')
    if not os.path.exists(path):
        die(f"Error: No public key found for '{party}'. Run 'init' first.")
    with open(path, "r") as f:
        print(f.read())
    

def cmd_list_types(party: str, entry: dict):
    """List the credential types this issuer can issue."""
    print(f"'{party}' can issue the following credential types:")
    for ctype in entry["allowed_credentials"]:
        print(f"  - {ctype}")
def cmd_check_revocation(args):
    with open(REVOCATION_FILE) as f:
        data = json.load(f)
    if args.jti in data["revoked_ids"]:
        print(f"[REVOKED] Credential '{args.jti}' is revoked.")
    else:
        print(f"[VALID]   Credential '{args.jti}' is not revoked.")
def cmd_issue(party: str, entry: dict, args):
    credential_types =args.type
    holder_key_id = args.holder
    subject_name = args.subject

    if(credential_types not in entry["allowed_credentials"]):
        die(f"Error: '{party}' cannot issue credential type '{credential_types}'.")
    
    key_id = entry["key_id"]
    dir = os.path.join(BASE_DIR, "issuer", 'issuer_keys', key_id)
    path = os.path.join(dir, 'private_key.pem')
    if not os.path.exists(path):
        die(f"No keys found for '{key_id}'. Run 'init' first.")
    private_key = load_private_key(path)
    public_key_path = os.path.join(dir, 'public_key.pem')
    holder_public_pem = load_public_key(os.path.join(BASE_DIR, "wallet", "device_keys", "public_key.pem"))



    if(args.claims):
        try:
            claims = json.loads(args.claims)
        except json.JSONDecodeError:
            die("Error: Claims must be a valid JSON string.")
    elif(credential_types in DATA):
        claims = dict(DATA[credential_types])
        if subject_name:
            if "given_name" in claims:
                claims["given_name"] = subject_name
        _info(f"Using default claim template for '{credential_types}'.")
    else:
        die(
            f"No default template for credential type '{credential_types}'.\n"
            f"Provide claims with: --claims '{{\"key\": \"value\", ...}}'"
        )

    # 5. Add metadata claims
    jti = str(uuid.uuid4())   # unique credential ID (used for revocation)
    claims["jti"] = jti
    claims["credential_type"] = credential_types

    # 6. Display what will be issued and ask for confirmation
    print()
    print("═" * 54)
    print(f"  Issuing Credential")
    print("═" * 54)
    print(f"  Issuer:  {entry['name']}")
    print(f"  Party:     {party}")
    print(f"  Type:    {credential_types}")
    print(f"  Holder key: {holder_key_id}")
    print(f"  Claims to be embedded (all hidden by default):")
    for k, v in claims.items():
        if k not in ("jti", "credential_type"):
            print(f"    {k}: {v}")
    print("═" * 54)

    if not args.yes:
        answer = input("\nIssue this credential? [y/N]: ").strip().lower()
        if answer != "y":
            print("[INFO]  Issuance cancelled.")
            sys.exit(0)

    # 7. Create the SD-JWT
    bundle = create_sd_jwt(
        claims=claims,
        issuer_private_key=private_key,
        issuer_id=party,
        holder_public_key_pem=holder_public_pem,
        credential_type=credential_types,
    )

    # 8. Persist to data/
    out_path = save_credential(bundle, credential_types)

    print()
    ok(f"Credential issued successfully.")
    _info(f"  Output file: {out_path}")
    _info(f"  Credential ID (jti): {jti}")
    _info(f"  Disclosable claims:  {[k for k in bundle['disclosures']]}")
    _info(f"  The wallet can now import this file.")


def cmd_revoke(did: str, entry: dict, args):
    """Add a credential ID to the revocation list."""
    add_to_revocation_list(args.jti)
    ok(f"Credential '{args.jti}' added to revocation list.")


# ── CLI entry point ───────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="issuer",
        description="Identity Wallet PoC — Credential Issuer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m issuer.issuer -p ugent init
  python -m issuer.issuer -p ugent issue --holder holder_device --type StudentID
  python -m issuer.issuer -p ugent issue --holder holder_device --type StudentID --subject Bob -y
  python -m issuer.issuer -p gov   issue --holder holder_device --type eID -y
  python -m issuer.issuer -p ugent list-types
  python -m issuer.issuer -p ugent show-key
  python -m issuer.issuer -p ugent revoke --jti <uuid>
        """,
    )

    parser.add_argument(
        "-p", "--party",
        required=True,
        choices=list(party_mapping.keys()),
        metavar="PARTY",
        help=f"Which issuer to act as. Choices: {', '.join(party_mapping)}",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # init
    p_init = sub.add_parser("init", help="Generate issuer key pair (run once)")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing keys")

    # show-key
    sub.add_parser("show-key", help="Print the issuer's public key PEM")

    # list-types
    sub.add_parser("list-types", help="List authorized credential types")

    # issue
    p_issue = sub.add_parser("issue", help="Issue a signed credential to a holder")
    p_issue.add_argument(
        "--holder",
        default="holder_device",
        metavar="KEY_ID",
        help="Key ID of the holder's device public key in data/keys/ (default: holder_device)",
    )
    p_issue.add_argument(
        "--type", "-t",
        required=True,
        metavar="TYPE",
        help="Credential type to issue (e.g. StudentID, eID, AgeProof)",
    )
    p_issue.add_argument(
        "--subject", "-s",
        default=None,
        metavar="NAME",
        help="Override the given_name in the default template",
    )
    p_issue.add_argument(
        "--claims",
        default=None,
        metavar="JSON",
        help='Custom claims as a JSON string, e.g. \'{"name": "Bob", "age": 22}\'',
    )
    p_issue.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Skip confirmation prompt",
    )

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke an issued credential by its jti")
    p_revoke.add_argument("--jti", required=True, help="The jti (credential ID) to revoke")

    p_check = sub.add_parser("check-revocation", help="Check if a credential is revoked")
    p_check.add_argument("--jti", required=True, help="The jti to check")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    did, entry = resolve_issuer_name(args.party)

    if args.command == "init":
        if getattr(args, "force", False):
            cmd_init_force(did, entry)
        else:
            cmd_init(did, entry)

    elif args.command == "show-key":
        cmd_show_key(did, entry)

    elif args.command == "list-types":
        cmd_list_types(did, entry)

    elif args.command == "issue":
        cmd_issue(did, entry, args)

    elif args.command == "revoke":
        cmd_revoke(did, entry, args)
    elif args.command == "check-revocation":
        cmd_check_revocation(args)

if __name__ == "__main__":
    main()
