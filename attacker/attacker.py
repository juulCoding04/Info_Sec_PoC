import argparse
import json
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Callable

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")
ATTACKER_KEY_DIR = os.path.join(BASE_DIR, "attacker", "attacker_keys")
DATA_DIR = os.path.join(BASE_DIR, "data")
ISSUED_CREDENTIALS_DIR = os.path.join(DATA_DIR, "issued_credentials")
TRUSTED_ISSUERS_FILE = os.path.join(DATA_DIR, "trusted_issuers.json")
WALLET_PUBLIC_KEY_FILE = os.path.join(BASE_DIR, "wallet", "device_keys", "public_key.pem")


CLAIM_TEMPLATES = {
    "student_id": {
        "first_name": "Mallory",
        "last_name": "Attacker",
        "date_of_birth": "01/01/2004",
        "university": "Ghent University",
        "faculty": "Engineering and Architecture",
        "degree": "Master of Science in Computer Science",
        "graduation_year": None,
        "student_id": "999999",
        "email": "mallory.attacker@ugent.be",
        "phone_number": "123456789",
        "valid_until": "30/09/2028",
    },
    "national_id": {
        "first_name": "Mallory",
        "last_name": "Attacker",
        "date_of_birth": "01/01/2004",
        "national_registration_number": "98.76.54-321.09",
        "expiration_date": "30/09/2034",
        "nationality": "Belgian",
        "gender": "Female",
    },
    "driving_license": {
        "first_name": "Mallory",
        "last_name": "Attacker",
        "date_of_birth": "01/01/2004",
        "license_number": "9999999",
        "date_achieved": "10/01/2022",
        "expiration_date": "10/01/2032",
        "issuing_authority": "Belgian Government",
        "categories": ["AM", "B"],
    },
}


def _info(message: str):
    print(f"[INFO] {message}")


def _ok(message: str):
    print(f"[OK]   {message}")


def die(message: str):
    print(f"[ERR]  {message}")
    sys.exit(1)


def ensure_attacker_keys(force: bool = False):
    from crypto.keys import generate_keypair, save_keypair

    private_key_path = os.path.join(ATTACKER_KEY_DIR, "private_key.pem")
    public_key_path = os.path.join(ATTACKER_KEY_DIR, "public_key.pem")

    if force or not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key, public_key = generate_keypair()
        save_keypair(private_key, public_key, ATTACKER_KEY_DIR)
        _ok("Attacker key pair generated.")
    else:
        _info("Using existing attacker key pair.")


def load_trusted_issuers() -> dict:
    if not os.path.exists(TRUSTED_ISSUERS_FILE):
        die("Trusted issuers registry not found. Expected data/trusted_issuers.json.")

    with open(TRUSTED_ISSUERS_FILE, "r") as file:
        return json.load(file)


def find_issuer(issuer_name: str) -> dict:
    registry = load_trusted_issuers()

    for issuer in registry.get("trusted_issuers", []):
        if issuer["name"] == issuer_name:
            return issuer

    known = ", ".join(i["name"] for i in registry.get("trusted_issuers", []))
    die(f"Unknown issuer '{issuer_name}'. Known issuers: {known}")


def default_credential_type(issuer: dict) -> str:
    allowed = issuer.get("allowed_credentials", [])
    if not allowed:
        die(f"Issuer '{issuer['name']}' has no allowed credentials in the registry.")
    return allowed[0]


def load_claims(credential_type: str, claims_json: str | None) -> dict:
    if claims_json:
        try:
            claims = json.loads(claims_json)
        except json.JSONDecodeError as exc:
            die(f"--claims must be valid JSON: {exc}")

        if not isinstance(claims, dict):
            die("--claims must decode to a JSON object.")
        return claims

    if credential_type not in CLAIM_TEMPLATES:
        known = ", ".join(sorted(CLAIM_TEMPLATES))
        die(
            f"No attacker claim template for '{credential_type}'. "
            f"Use --claims '{{...}}' or pick one of: {known}"
        )

    return dict(CLAIM_TEMPLATES[credential_type])


def get_public_key_for_bundle(issuer: dict, public_key_mode: str) -> str:
    if public_key_mode == "attacker":
        path = os.path.join(ATTACKER_KEY_DIR, "public_key.pem")
    elif public_key_mode == "registered":
        path = os.path.join(BASE_DIR, issuer["public_key_path"])
    else:
        die(f"Unknown public key mode '{public_key_mode}'.")

    if not os.path.exists(path):
        die(f"Public key file not found: {path}")

    with open(path, "r") as file:
        return file.read()


def write_forged_credential(bundle: dict, issuer_name: str, credential_type: str, jti: str) -> str:
    os.makedirs(ISSUED_CREDENTIALS_DIR, exist_ok=True)

    issuer_slug = issuer_name.lower().replace(" ", "_")
    filename = f"forged_{issuer_slug}_{credential_type}_{jti}.json"
    out_path = os.path.join(ISSUED_CREDENTIALS_DIR, filename)

    with open(out_path, "w") as file:
        json.dump(bundle, file, indent=2)

    return out_path


def attack_fake_issuer(args) -> str:
    from crypto.keys import load_private_key, load_public_key
    from crypto.sd_jwt import create_sd_jwt

    issuer = find_issuer(args.issuer)
    credential_type = args.credential_type or default_credential_type(issuer)

    if credential_type not in issuer.get("allowed_credentials", []):
        allowed = ", ".join(issuer.get("allowed_credentials", []))
        die(
            f"'{issuer['name']}' is not registered for credential type '{credential_type}'. "
            f"Allowed: {allowed}"
        )

    if not os.path.exists(WALLET_PUBLIC_KEY_FILE):
        die("Wallet public key not found. Run: python scripts/generate_keys.py")

    ensure_attacker_keys(force=args.force_keys)

    attacker_private_key = load_private_key(os.path.join(ATTACKER_KEY_DIR, "private_key.pem"))
    wallet_public_key = load_public_key(WALLET_PUBLIC_KEY_FILE)

    jti = str(uuid.uuid4())
    claims = load_claims(credential_type, args.claims)
    claims["jti"] = jti
    claims["credential_type"] = credential_type

    forged = create_sd_jwt(
        claims=claims,
        issuer_private_key=attacker_private_key,
        issuer_id=issuer["name"],
        holder_public_key_pem=wallet_public_key,
        credential_type=credential_type,
    )

    forged["issuer_public_key"] = get_public_key_for_bundle(issuer, args.public_key_mode)
    forged["attack_metadata"] = {
        "attack": "fake-issuer",
        "description": "Credential claims to come from a trusted issuer but is signed by the attacker.",
        "claimed_issuer": issuer["name"],
        "signed_by": "attacker",
        "public_key_mode": args.public_key_mode,
        "expected_wallet_result": (
            "Rejected by trusted issuer public-key check"
            if args.public_key_mode == "attacker"
            else "Rejected by issuer signature verification"
        ),
    }

    out_path = write_forged_credential(forged, issuer["name"], credential_type, jti)

    _ok("Forged credential created.")
    _info(f"Claimed issuer: {issuer['name']}")
    _info(f"Credential type: {credential_type}")
    _info(f"Public key mode: {args.public_key_mode}")
    _info(f"Expected wallet result: {forged['attack_metadata']['expected_wallet_result']}")
    _info(f"Output file: {out_path}")
    return out_path


@dataclass(frozen=True)
class AttackSpec:
    name: str
    description: str
    configure_parser: Callable[[argparse.ArgumentParser], None]
    run: Callable[[argparse.Namespace], str | None]


def configure_fake_issuer_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "--issuer",
        default="UGent",
        help="Trusted issuer name to impersonate. Default: UGent",
    )
    parser.add_argument(
        "--type",
        dest="credential_type",
        default=None,
        help="Credential type to forge. Defaults to the issuer's first allowed type.",
    )
    parser.add_argument(
        "--public-key-mode",
        choices=["attacker", "registered"],
        default="attacker",
        help=(
            "Which public key to include in the forged bundle. "
            "'attacker' should fail trust checking; 'registered' should fail signature verification."
        ),
    )
    parser.add_argument(
        "--claims",
        default=None,
        help='Optional JSON claims object, for example: \'{"first_name":"Mallory"}\'',
    )
    parser.add_argument(
        "--force-keys",
        action="store_true",
        help="Regenerate the attacker key pair before forging.",
    )


ATTACKS = {
    "fake-issuer": AttackSpec(
        name="fake-issuer",
        description="Forge a credential that impersonates a trusted official issuer.",
        configure_parser=configure_fake_issuer_parser,
        run=attack_fake_issuer,
    ),
}


def list_attacks():
    print("\nAvailable attacks")
    print("=" * 40)
    for attack in ATTACKS.values():
        print(f"- {attack.name}: {attack.description}")
    print("")


def prompt_choice(prompt: str, choices: list[str], default: str | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ").strip()
        if not value and default:
            return default
        if value in choices:
            return value
        print(f"Choose one of: {', '.join(choices)}")


def run_fake_issuer_interactive():
    registry = load_trusted_issuers()
    issuers = [issuer["name"] for issuer in registry.get("trusted_issuers", [])]
    if not issuers:
        die("No trusted issuers found in data/trusted_issuers.json.")

    print("\nFake issuer attack")
    print("=" * 40)
    issuer_name = prompt_choice("Issuer to impersonate", issuers, "UGent" if "UGent" in issuers else issuers[0])
    issuer = find_issuer(issuer_name)

    allowed_types = issuer.get("allowed_credentials", [])
    credential_type = prompt_choice("Credential type", allowed_types, default_credential_type(issuer))
    public_key_mode = prompt_choice(
        "Public key mode",
        ["attacker", "registered"],
        "attacker",
    )

    print("\nClaim templates are used by default.")
    print("Press ENTER to continue, or paste a JSON object to override the claims.")
    claims = input("> ").strip() or None

    args = argparse.Namespace(
        issuer=issuer_name,
        credential_type=credential_type,
        public_key_mode=public_key_mode,
        claims=claims,
        force_keys=False,
    )
    attack_fake_issuer(args)


def interactive_menu():
    while True:
        print("\n" + "=" * 40)
        print("Attacker CLI")
        print("=" * 40)
        attacks = list(ATTACKS.values())
        for index, attack in enumerate(attacks, 1):
            print(f"[{index}] {attack.name} - {attack.description}")
        print("[l] List attacks")
        print("[q] Quit")

        choice = input("\nChoose an attack: ").strip().lower()
        if choice == "q":
            print("\nQuitting...")
            return
        if choice == "l":
            list_attacks()
            continue

        try:
            attack = attacks[int(choice) - 1]
        except (ValueError, IndexError):
            print("[ERR] Invalid choice.")
            continue

        if attack.name == "fake-issuer":
            run_fake_issuer_interactive()
        else:
            die(f"No interactive runner registered for '{attack.name}'.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attacker",
        description="Identity Wallet PoC - attack demonstrations",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List available attacks")

    run_parser = subparsers.add_parser("run", help="Run a specific attack")
    run_subparsers = run_parser.add_subparsers(dest="attack")

    for attack in ATTACKS.values():
        attack_parser = run_subparsers.add_parser(attack.name, help=attack.description)
        attack.configure_parser(attack_parser)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        interactive_menu()
        return

    if args.command == "list":
        list_attacks()
        return

    if args.command == "run":
        if args.attack is None:
            parser.error("run requires an attack name")

        ATTACKS[args.attack].run(args)
        return

    parser.error(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
