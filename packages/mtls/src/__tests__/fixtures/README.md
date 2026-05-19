# mTLS PKI Test Fixtures

P-256 ECDSA certificate chain for `pki.test.mts` chain-walk regression coverage.

## Files

- `root.pem` — self-signed CA (10 year validity, `CA:TRUE`, `keyCertSign`).
- `intermediate.pem` — signed by `root`, `CA:TRUE`, `keyCertSign` (5 year validity).
- `leaf.pem` — signed by `intermediate`, `CA:FALSE`, `clientAuth` EKU (1 year validity).
- `bad-intermediate.pem` — signed by `root`, `CA:FALSE` (1825-day validity). Used by the
  RFC 5280 §4.2.1.9 regression: a non-CA cannot sign certs.
- `leaf-bad-chain.pem` — signed by `bad-intermediate`, `CA:FALSE` (1 year validity).
  Used as the leaf in the "intermediate has `CA:FALSE`" rejection test.

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

Keys are not committed — only the certs are needed at test time (verification
uses public keys embedded in the chain).
