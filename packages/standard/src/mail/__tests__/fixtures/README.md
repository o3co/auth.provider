# SMTP relay test fixtures

Last updated: 2026-09-30

## Responsibility

The certificate the SMTP sender's tests secure a relay with: the scripted relay ([`support/scriptedRelay.mts`](../support/scriptedRelay.mts)) and the Mailpit container. A test trusts `relay-ca.pem` explicitly; the sender never turns certificate verification off. The key is a test key for these files alone. PEM files carry no header comment, so this README says what each one is.

## Files

- `relay-ca.pem` — a self-signed CA, `CN=Test SMTP Relay CA` (P-256, `CA:TRUE`, `keyCertSign`, 100-year validity, so no test starts failing on a date).
- `relay-cert.pem` — signed by `relay-ca.pem`: `CN=localhost`, `subjectAltName` `DNS:localhost`, `IP:127.0.0.1`, `IP:::1`, `serverAuth`, `CA:FALSE` (100-year validity).
- `relay-key.pem` — the private key of `relay-cert.pem` (P-256, PKCS#8, unencrypted).

Minted with OpenSSL 3:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -sha256 -days 36500 -subj "/CN=Test SMTP Relay CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out relay-ca.pem
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out relay-key.pem
openssl req -new -key relay-key.pem -subj "/CN=localhost" -out relay.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n' > ext.cnf
openssl x509 -req -in relay.csr -CA relay-ca.pem -CAkey ca-key.pem -CAcreateserial -sha256 -days 36500 -extfile ext.cnf -out relay-cert.pem
```

The CA's key was discarded.
