# Identity Wallet PoC - Architecture

## Overview
This proof-of-concept simulates a digital identity wallet with three core components: an issuer, a wallet holder and a verifier. An attacker script will also demonstrate how specific attacks are detected and prevented.

Communication between components will happen via JSON files in the `data/` directory, representing network messages. hardware security (TEE/Secure Element) is simulated using key (.pem) files on disk.

---

## Project structure
identity-wallet/
│
├── crypto/                  
│   ├── keys.py             
│   ├── signing.py         
│   ├── sd_jwt.py         
│   └── registry.py      
│
├── issuer/             
│   ├── issuer.py      
│   └── issuer_keys/  
│       ├── ugent/
│       │   ├── private_key.pem   
│       │   └── public_key.pem
│       └── belgian_government/
│           ├── private_key.pem
│           └── public_key.pem
│
├── wallet/                  
│   ├── wallet.py           
│   ├── device_keys/       
│   │   ├── private_key.pem  
│   │   └── public_key.pem
│   └── storage/
│       └── credentials/    
│
├── verifier/              
│   ├── verifier.py       
│   └── verifier_keys/   
│       ├── private_key.pem  
│       └── public_key.pem
│
├── attacker/               
│   ├── attacker.py        
│   └── attacker_keys/    
│       ├── private_key.pem  
│       └── public_key.pem
│
├── data/                   
│   ├── trusted_issuers.json 
│   ├── revocation_list.json
│   ├── issued_credentials/  
│   └── presentations/      
│
├── scripts/
│   └── generate_keys.py   
│
├── test/                 
│   ├── keys/
│   │   └── test_key_gen.py
│   ├── signing/
│   │   └── test_signing.py
│
├── docs/
│   ├── architecture.md      
│   └── simplifications.md  
│
├── .gitignore
├── README.md
└── requirements.txt

---

## Key rules

### What to commit
- crypto/*.py
- issuer/issuer.py
- wallet/wallet.py
- verifier/verifier.py
- attacker/attacker.py
- data/trusted_issuers.json
- data/revocation_list.json
- scripts/generate_keys.py
- test/*/*.py
- docs/*.md
- README.md
- requirements.txt

### What to never commit
- any *.pem file (private or public)
- wallet/storage/credentials
- data/issued_credentials
- data/presentations/

---

## Cryptographic design

### Algorithms
| Purpose | Algorithm | Key length |
|---------|-----------|------------|
| Credential signing | ECDSA P-256 | 256-bit |
| Device binding | ECDSA P-256 | 256-bit |
| Storage encryption | AES-256-GCM | 256-bit |
| Selective disclosure | SD-JWT | — |
| Hashing | SHA-256 | 256-bit |

### Key ownership
| Party | Key location | Purpose |
|-------|-------------|---------|
| UGent | issuer/issuer_keys/ugent/ | Signs student credentials |
| Belgian Government | issuer/issuer_keys/belgian_government/ | Signs national credentials |
| Wallet/Holder | wallet/device_keys/ | Device binding, signs presentations |
| Verifier | verifier/verifier_keys/ | Identifies itself to wallet |
| Attacker | attacker/attacker_keys/ | Used in attack demos |

### Simulate TEE
In a real system the wallet's private keys never leave the TEE and every signing requires hardware-confirmed user presence (biometric).

In the PoC:
- Private keys are stored as PEM files on disk
- Biometric confirmation is simulated via a key press
- We mark every place in the code that would happen inside the TEE with `# [TEE OPERATION]`.

---

## Credetial lifecycle

### 1. Issuance

### 2. Presentation

### 3. Revocation

---

## Data files

## `data/trusted_issuers.json`
Registry of issuers the wallet accepts credentials from. This is manually mocked in this PoC.

## `data/revocation_list.json`
List of revoked credential IDs. Checked by verifier at each presentation. Checked by wallet before presentation.

## `data/presentations/<id>_presentation.json`
Selective disclosure presentation produced by the wallet. Simulates transmission to verifier.

---

## Adding a new issuer

1. Add the issuer to `scripts/generate_keys.py`
```python
parties = [
    ...
    "issuer/issuer_keys/new_issuer",
]
```
2. Run the key generation script:
```bash
python scripts/generate_keys.py
```
3. Add the issuer to `data/trusted_issuers.json`
```json
{
  "name": "New Issuer",
  "key_id": "new_issuer",
  "public_key_path": "issuer/issuer_keys/new_issuer/public_key.pem",
  "allowed_credentials": ["credential_type"]
}
```

That's it!

---

## Adding a new credential type

1. Add the credential type to the issuer's `allowed_credentials` in `trusted_issuers.json`
2. Add a default claim template to the `DATA` dict in `issuer/issuer.py`
3. The wallet and verifier handle any credential type generically, no changes needed here

---

## Crypto module - Reference manual

### `crypto/keys.py`
```python
generate_keypair()              # → (private_key, public_key)
save_keypair(priv, pub, dir)    # → saves PEM files to directory
load_private_key(path)          # → private_key object
load_public_key(path)           # → public_key object
```

### `crypto/signing.py`
```python
sign(data: dict, private_key)           # → base64 signature string
verify(data, signature, public_key)     # → bool
```

---

## Important design notes

**`crypto/` is generic. This means no hardcoded paths should be coded here**
All path logic belongs to the party scripts (issuer, wallet or verifier), not in the crypto dir itself

**Revoked credentials are kept not deleted**
Revocation means "no longer valid", not "never existed" or "deleted". 
