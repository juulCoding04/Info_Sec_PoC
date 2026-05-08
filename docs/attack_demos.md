# Attack demonstrations

The attacker module can be run either as an interactive CLI or with direct
commands. Direct commands are useful for repeatable demos and tests.

```bash
python -m attacker.attacker # Interactive CLI
python -m attacker.attacker list # List available attacks
python -m attacker.attacker run fake-issuer # Run fake issuer attack
```

## Fake issuer

The fake issuer attack creates a credential that claims to be issued by a
trusted issuer, but is signed with the attacker's private key. The forged
credential is written to `data/issued_credentials/`, where the wallet can try
to import it through the normal "Receive new credentials" flow.

Default demo:

```bash
python -m attacker.attacker run fake-issuer
```

This impersonates `UGent`, creates a forged `student_id`, and includes the
attacker public key in the credential bundle. The wallet should reject this at
the trusted issuer public-key check.

Signature-verification demo:

```bash
python -m attacker.attacker run fake-issuer --public-key-mode registered
```

This still signs with the attacker private key, but includes the real registered
issuer public key in the credential bundle. The trusted issuer check should
pass, but issuer signature verification should fail.

Other examples:

```bash
python -m attacker.attacker run fake-issuer --issuer "Belgian Government" --type national_id
python -m attacker.attacker run fake-issuer --issuer UGent --type student_id --claims "{\"first_name\":\"Mallory\",\"last_name\":\"Attacker\"}"
```

## Adding attacks

Add a new attack by creating:

1. A function that performs the attack.
2. A `configure_<attack>_parser` function for command-line options.
3. A new entry in the `ATTACKS` registry in `attacker/attacker.py`.

The interactive menu is intentionally thin: it lists registered attacks and can
add a custom prompt flow for attacks that benefit from guided input.
