# Attacker CLI

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

## Fake Issuer Choices

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

## Tampering Choices

The tamper credential attack asks where to take the source credential from and
what kind of tampering to perform.

`jwt-payload` changes a signed JWT payload field, such as `credential_type`,
`iss`, `jti`, or `exp`. This should break the issuer signature.

`disclosure` changes one selective-disclosure value, such as `first_name` or
`student_id`. This should be detected by checking whether the changed disclosure
still hashes to one of the signed `_sd` values.

## Checking Results

After an attack creates a file in `data/issued_credentials/`, open the wallet:

```bash
python -m wallet.wallet
```

Choose `Receive new credentials` and select the attack file. A successful
defense means the wallet rejects the credential before storing it.

Expected outcomes:

- Fake issuer with attacker key: rejected by trusted issuer public-key check.
- Fake issuer with registered key: rejected by issuer signature verification.
- JWT payload tampering: rejected by issuer signature verification.
- Disclosure tampering: rejected if disclosure hash verification is implemented.

If disclosure tampering is accepted, that indicates the wallet still needs a
disclosure hash verification step.
