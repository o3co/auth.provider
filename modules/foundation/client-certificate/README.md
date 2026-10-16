# client-certificate

## Responsibilities
- Reads the client's certificate that a trusted proxy forwards, in the form the operator names.

## Not here
- Which peers are trusted proxies (`request-source`); what a certificate holds (its reader).

## Offers
- The forwarded certificate: its leaf and chain, or `malformed`, as `request-source`'s source carries it.
- `certificateForwarding`: whether the operator named where certificates are forwarded.
- `certificateSettings`, the schema part `http`'s section takes as `client-certificate` (its keys in the settings list).

## Invariants
- No client's certificate is read unless `client-certificate` is set.
- The client's certificate is read only from a direct peer that is a trusted proxy, each header at most 16 KiB.
- A certificate sent by another peer is ignored, and logged at most once a minute.
- Whether the proxy removes the header a client sends is the proxy's to ensure.
- A certificate read is handed on as copies of its bytes, frozen.
- PEM: one certificate block, URL-encoded or not, with nothing but whitespace beside it.
- XFCC: exactly one element; several, repeated header lines among them, are `malformed`.
- XFCC: outside quotes, `,` parts elements and `;` fields; a quoted value takes `\` before any character; a field needs `=`, and only spaces follow a closing quote.
- XFCC: Hash, Cert, Chain and Subject come at most once, in any case.
- XFCC: Cert is one URL-encoded certificate block and nothing else, Chain is certificate blocks only, and Hash is the leaf's SHA-256.

## Depends on
- `kernel` (the clock of the warning), `zod`.
