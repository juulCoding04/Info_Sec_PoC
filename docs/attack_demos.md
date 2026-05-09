# Attacker Demo

The attacker component is an interactive CLI for creating attack demo files.
It does not attack a live network service. Instead, it writes manipulated
credential files into the project folders so the wallet can process them through
its normal flows.

Start the attacker from the project root:

```bash
python -m attacker.attacker
```

The menu lists the available attacks. Choose an attack by entering its number.
The CLI then asks for the values it needs, such as which issuer to impersonate,
which credential type to forge, or which credential file to tamper with.

## Menu Options

`List attacks` shows the attacks currently registered in `attacker/attacker.py`.

`Show issuer/credential options` lists the issuers and credential types from
`data/trusted_issuers.json`. These are the identities an attacker can try to
impersonate in the fake issuer demo.

`fake-issuer` creates a new credential that claims to come from a trusted issuer
but is signed by the attacker. The generated credential is written to
`data/issued_credentials/`. Test it by opening the wallet and choosing
`Receive new credentials`.

`tamper-credential` modifies an existing credential without re-signing it. The
CLI can use either pending credentials from `data/issued_credentials/` or stored
wallet credentials from `wallet/storage/credentials/` as the source. The
tampered copy is written to `data/issued_credentials/` by default, so it can be
tested through the wallet import flow.

`clone-credential` does not literally copy an existing credential file. Because
the PoC only has one wallet, it creates a fresh valid credential using a trusted
issuer key, binds it to the attacker's device key, and places it in the incoming
credential inbox: `data/issued_credentials/`. This represents the situation
where a valid credential from another device is offered to this wallet for
import. The issuer signature should still be valid, but the wallet should reject
the credential during holder binding before storing it.

`replay-presentation` copies an existing presentation file byte-for-byte inside
`data/presentations/`. No JSON fields are changed. This simulates an attacker
capturing a valid presentation and submitting it again later.

`tamper-presentation` modifies one field inside an existing presentation without
updating `device_sig`. This simulates an attacker changing the presentation
while it is travelling from wallet to verifier.

## Fake Issuer

The fake issuer attack asks for three important choices.

`Issuer to impersonate` is the trusted issuer name the forged credential will
claim to come from, for example `UGent` or `Belgian Government`.

`Credential type` is the credential the attacker wants to forge, such as
`student_id`, `Diplomas`, `national_id`, `driving_license`, or
`international_passport`.

`Public key mode` decides which public key is placed inside the forged
credential:

- `attacker`: the credential claims to come from a trusted issuer but includes
  the attacker's public key. The wallet should reject it during the trusted
  issuer public-key check.
- `registered`: the credential includes the real registered issuer public key,
  but the JWT is still signed with the attacker's private key. The wallet should
  reject it during issuer signature verification.

## Tampering with credentials

The tamper credential attack asks where to take the source credential from and
what kind of tampering to perform.

`jwt-payload` changes a signed JWT payload field, such as `credential_type`,
`iss`, `jti`, or `exp`. This should break the issuer signature.

`disclosure` changes one selective-disclosure value, such as `first_name` or
`student_id`. This should be detected by checking whether the changed disclosure
still hashes to one of the signed `_sd` values.

## Cloning credentials

The clone credential attack asks for the issuer and credential type to use for
the sample foreign credential. The CLI creates the credential using the issuer's
real signing key but binds it to the attacker's device key in
`attacker/attacker_keys/`.

This is a setup shortcut for the PoC, not a literal file-copy operation. It
represents a valid credential that was issued to another device and then placed
in the current wallet's import flow. The wallet should reject it before storage
because the public key in the credential's `cnf` claim does not match
`wallet/device_keys/public_key.pem`.

## Replaying presentations

The replay presentation attack asks for an existing presentation file from
`data/presentations/`. The CLI creates a second file with the same contents.

This should be rejected only when the verifier tracks which nonces it issued or
which nonces have already been used. The current verifier checks that a nonce is
present, but does not yet remember used nonces.

## Tampering with presentations

The tamper presentation attack asks for a presentation file, a field to change,
and a new value. Useful fields are `nonce`, `issuer_jwt`, `device_sig`, or a
specific disclosure such as `disclosures[0]`.

The wallet signs the presentation data before writing the presentation file. If
an attacker changes any signed field afterward, the verifier should reject the
presentation during device signature verification.

## Checking Results

After an attack creates a file in the incoming credential inbox,
`data/issued_credentials/`, open the wallet:

```bash
python -m wallet.wallet
```

Choose `Receive new credentials` and select the attack file. In this PoC,
`Receive new credentials` means the wallet is reviewing pending incoming files
before importing them into `wallet/storage/credentials/`. A successful defense
means the wallet rejects the credential before storing it.

Expected outcomes:

- Fake issuer with attacker key: rejected by trusted issuer public-key check.
- Fake issuer with registered key: rejected by issuer signature verification.
- JWT payload tampering: rejected by issuer signature verification.
- Disclosure tampering: rejected if disclosure hash verification is implemented.
- Cloned credential: rejected by holder binding check.
- Replayed presentation: accepted until nonce replay protection is implemented.
- Tampered presentation: rejected by device signature verification.

If disclosure tampering is accepted, that indicates the wallet still needs a
disclosure hash verification step.
