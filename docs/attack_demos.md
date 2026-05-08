# Attack demonstrations

The attacker module can be run either as an interactive CLI or with direct
commands. Direct commands are useful for repeatable demos and tests.

```bash
python -m attacker.attacker # Interactive CLI
python -m attacker.attacker list # List available attacks
python -m attacker.attacker options # List issuers and credential types
python -m attacker.attacker run fake-issuer --issuer UGent --type student_id --public-key-mode attacker
```

## Fake issuer

The fake issuer attack creates a credential that claims to be issued by a
trusted issuer, but is signed with the attacker's private key. The forged
credential is written to `data/issued_credentials/`, where the wallet can try
to import it through the normal "Receive new credentials" flow.

Trust-list demo:

```bash
python -m attacker.attacker run fake-issuer --issuer UGent --type student_id --public-key-mode attacker
```

This includes the attacker public key in the credential bundle. The wallet
should reject this at the trusted issuer public-key check.

Signature-verification demo:

```bash
python -m attacker.attacker run fake-issuer --issuer UGent --type student_id --public-key-mode registered
```

This still signs with the attacker private key, but includes the real registered
issuer public key in the credential bundle. The trusted issuer check should
pass, but issuer signature verification should fail.

### Public key mode

`--public-key-mode` controls which public key the attacker puts in the forged
credential file:

- `attacker`: the forged credential says `iss = UGent`, but embeds the
  attacker's public key. The wallet should reject it because the embedded key
  does not match UGent's registered key.
- `registered`: the forged credential says `iss = UGent` and embeds UGent's
  real registered public key, but the JWT was still signed by the attacker. The
  wallet should get past the trusted issuer check and then reject it because the
  issuer signature is invalid.

### Issuer and credential choices

The available impersonation targets come from `data/trusted_issuers.json`.
Use this command to list them:

```bash
python -m attacker.attacker options
```

Other examples:

```bash
python -m attacker.attacker run fake-issuer --issuer "Belgian Government" --type national_id --public-key-mode attacker
python -m attacker.attacker run fake-issuer --issuer "Belgian Government" --type driving_license --public-key-mode attacker
python -m attacker.attacker run fake-issuer --issuer "Belgian Government" --type international_passport --public-key-mode registered
python -m attacker.attacker run fake-issuer --issuer UGent --type student_id --public-key-mode attacker --claims "{\"first_name\":\"Mallory\",\"last_name\":\"Attacker\"}"
python -m attacker.attacker run fake-issuer --issuer UGent --type Diplomas --public-key-mode registered
```

## Adding attacks

Add a new attack by creating:

1. A function that performs the attack.
2. A `configure_<attack>_parser` function for command-line options.
3. A new entry in the `ATTACKS` registry in `attacker/attacker.py`.

The interactive menu is intentionally thin: it lists registered attacks and can
add a custom prompt flow for attacks that benefit from guided input.
