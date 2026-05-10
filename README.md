# Identity Wallet - Proof of Concept
Information Security Assignment - Group 6
Juul Christiaens, Michiel De Cock, Gilles Maes, Jelle Parmentier, Robbe Vanhalst & Kobe Vlemings

## What is it
A proof-of-concept CLI application demonstrating the security mechanisms of a digital identity wallet. The system simulates credential issuance, selective disclosure, and presentation between three parties: an issuer, a wallet holder and a verifier.

An attacker script demonstrates how specific attacks are prevented.

## Project structure
```bash
|-- Info_Sec_PoC
|   |-- crypto/         # Shared cryptographic utilities (key, signing, SD-JWT)
|   |-- issuer/         # Issuer script (issues signed credentials)
|   |-- wallet/         # Interactive wallet CLI (the user-facing application)
|   |-- verifier/       # Cerifier script (requests and validates presentations)
|   |-- attacker/       # Attack demonstration scripts
|   |-- docs/            # Architecture and design documentation
```

## Getting started

!!!Before working on this project, make sure you read the architecture.md documentation in the docs/ directory!!!

### Requirements
- Python 3.10 or higher

### Setup
Clone the repository and navigate to it:
```bash
git clone https://github.com/juulCoding04/Info_Sec_PoC.git
cd Info_Sec_PoC
```

Create and activate a virtual environment:
```bash
# Mac/Linux
python -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
venv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

Run script to initialize all keys
```bash
python scripts/generate_keys.py
```


## Issuer commands

### setup
Run these commands once for each the issuers defined in trusted_issuers.json to check the keys have been generated:
```bash
python -m issuer.issuer -p <issuer> init
```
with <issuer> the name of the issuer as defined in the party_mapping dict in issuer.py
This will create keys for the issuers if generate_keys.py failed. Add --force to overwrite the existing keys. 

### List credential types of issuer

```bash
python -m issuer.issuer -p <issuer> list-types
```
Will provide all the credentials (ID, Driver Licence, Diploma's, ...) the issuer has acces to.

### Issue credentials

```bash
python -m issuer.issuer -p <issuer> issue --holder wallet --type <credential> -y
```
This will issue a credential the issuer has acces to for the holder (in our case the wallet?) and creates a <credential>_credential.json file in the data subfolder.

### Revoke credentials
```bash
python -m issuer.issuer -p <issuer> revoke --jti <Credential ID (jti)>
```
the Credential ID (jti) is printed when issueing a credential.


## Verifier commands

### Setup
Run once to generate the verifier's key pair:
```bash
python -m verifier.verifier init
```
Add `--force` to overwrite existing keys.

### List pending presentations
```bash
python -m verifier.verifier list
```
Lists all presentation files waiting in `data/presentations/`, showing credential type, issuer and JTI for each.

### Verify a presentation
```bash
python -m verifier.verifier verify --presentation <filename>
```
The filename can be just the file name (resolved relative to `data/presentations/`) or a full path.

This runs the full verification pipeline:
1. Device signature — confirms the presentation was created by the wallet and not tampered with
2. Nonce present — ensures the presentation includes a nonce (replay attack detection)
3. Trusted issuer — checks the issuer against `data/trusted_issuers.json`
4. Issuer SD-JWT signature — verifies the cryptographic signature of the issuer
5. Disclosure integrity — verifies each disclosed claim is committed in the SD-JWT
6. Revocation check — checks the credential JTI against `data/revocation_list.json`

