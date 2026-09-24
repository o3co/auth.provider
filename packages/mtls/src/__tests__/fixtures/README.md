# mTLS PKI Test Fixtures

Last updated: 2026-09-24

## Responsibility

Committed P-256 ECDSA certificates — three small chains, one per root (`root`,
`attacker-root`, `ext-root`) — for the tests that
need a real certificate rather than one they build: the narrow-mode chain walk
([`pki.test.mts`](../pki.test.mts)), and the certificate a request presents in
the mechanism, module and DPoP + mTLS tests
([`extractor.test.mts`](../extractor.test.mts),
[`module.integration.test.mts`](../module.integration.test.mts),
[`dual-mechanism.integration.test.mts`](../dual-mechanism.integration.test.mts),
[`fullPki/module.test.mts`](../fullPki/module.test.mts)). They are fixtures
because each shape is a regression someone had to reason about, and a fixed
file keeps that shape byte-identical from run to run.

The `full-pki` validator's own tests — every test under `fullPki/` except `module.test.mts`, which uses `root.pem` for the certificate a request presents — do not use them: they need name
constraints, path lengths, CRLs and many more shapes, and mint certificates in
process ([`fullPki/pkiFactory.mts`](../fullPki/pkiFactory.mts)) so that no
test starts failing on a calendar date. PEM files carry no header comment, so
this README is where what each one is for is written down.

## Files

- `root.pem` — self-signed CA (10 year validity, `CA:TRUE`, `keyCertSign`).
- `intermediate.pem` — signed by `root`, `CA:TRUE`, `keyCertSign` (5 year validity).
- `leaf.pem` — signed by `intermediate`, `CA:FALSE`, `clientAuth` EKU (1 year validity).
- `bad-intermediate.pem` — signed by `root`, `CA:FALSE` (1825-day validity). Used by the
  RFC 5280 §4.2.1.9 regression: a non-CA cannot sign certs.
- `leaf-bad-chain.pem` — signed by `bad-intermediate`, `CA:FALSE` (1 year validity).
  Used as the leaf in the "intermediate has `CA:FALSE`" rejection test.
- `attacker-root.pem` — adversarial self-signed root with **the same DN** (`CN=Test Root CA`)
  as `root.pem`, but a **different** private key. Used in the forged-cert
  regression: an attacker mints a leaf with matching issuer DN.
- `attacker-leaf.pem` — signed by `attacker-root`, with issuer DN matching the
  legitimate `root`. Pins the "checkIssued alone is insufficient — explicit
  signature verification is required" contract: validating this leaf against
  the legitimate `root.pem` MUST reject (it was not actually signed by the
  legitimate root, just labelled as if it were). Deliberately carries **no**
  `extendedKeyUsage`, which is also what lets it exercise the leaf-profile
  checks' "absence is unconstrained" branch.

### Leaf-profile chain (`ext-*`, issue #280)

The third chain: independent and single-hop, its leaves differ **only** in
`basicConstraints` / `extendedKeyUsage`, so a rejection cannot be caused by
anything else. Separate from the chains above so those fixtures — and the
AKID-serial nuance `pki.test.mts` documents — stay byte-identical.

Minted with a 10-year window, and the tests using them read the real clock
rather than the fixed `NOW` used by the chain-walk tests.

- `ext-root.pem` — self-signed CA (`CA:TRUE`, `keyCertSign`).
- `ext-leaf-clientauth.pem` — `CA:FALSE`, EKU `clientAuth`. The accepted case.
- `ext-leaf-serverauth.pem` — `CA:FALSE`, EKU `serverAuth` only. A server
  certificate presented as a client credential; MUST reject.
- `ext-leaf-no-eku.pem` — `CA:FALSE`, no EKU extension. MUST be **accepted**:
  RFC 5280 §4.2.1.12 makes the extension a restriction, not a grant.
- `ext-leaf-ca-true.pem` — `CA:TRUE`, EKU `clientAuth`. A CA certificate is not
  a client credential; MUST reject.

## Regeneration

If validity windows expire, regenerate with the same shapes:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout root.key -out root.pem \
  -nodes -days 3650 -subj "/CN=Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout intermediate.key -out intermediate.csr \
  -nodes -subj "/CN=Test Intermediate CA"
openssl x509 -req -in intermediate.csr -CA root.pem -CAkey root.key -CAcreateserial \
  -out intermediate.pem -days 1825 \
  -extfile <(printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n')

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout leaf.key -out leaf.csr \
  -nodes -subj "/CN=Test Leaf"
openssl x509 -req -in leaf.csr -CA intermediate.pem -CAkey intermediate.key -CAcreateserial \
  -out leaf.pem -days 365 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout badint.key -out badint.csr \
  -nodes -subj "/CN=Test Bad Intermediate (non-CA)"
openssl x509 -req -in badint.csr -CA root.pem -CAkey root.key -CAcreateserial \
  -out bad-intermediate.pem -days 1825 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n')

openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout leaf-bc.key -out leaf-bc.csr \
  -nodes -subj "/CN=Test Leaf Bad Chain"
openssl x509 -req -in leaf-bc.csr -CA bad-intermediate.pem -CAkey badint.key -CAcreateserial \
  -out leaf-bad-chain.pem -days 365 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
```

The `ext-*` leaf-profile chain (10-year windows, so regeneration should be rare):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout ext-root.key -out ext-root.pem \
  -nodes -days 3650 -subj "/CN=Test Ext Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# $1 = output basename, $2 = subject CN, $3 = extension file contents
mkleaf() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout "$1.key" -out "$1.csr" \
    -nodes -subj "/CN=$2"
  printf "%b" "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ext-root.pem -CAkey ext-root.key -CAcreateserial \
    -out "$1.pem" -days 3650 -extfile "$1.ext"
}

mkleaf ext-leaf-clientauth "Test Ext Leaf ClientAuth" \
  'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n'
mkleaf ext-leaf-serverauth "Test Ext Leaf ServerAuth" \
  'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n'
mkleaf ext-leaf-no-eku "Test Ext Leaf No EKU" \
  'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
mkleaf ext-leaf-ca-true "Test Ext Leaf CA True" \
  'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyCertSign\nextendedKeyUsage=clientAuth\n'
```

Keys are not committed — only the certs are needed at test time (verification
uses public keys embedded in the chain).
