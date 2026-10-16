# clients

## Responsibilities
- Looks up and authenticates clients, checking and freezing their records at the boundary, with built-in methods `client_secret_basic`, `client_secret_post` and `none`.

## Not here
- What each metadata field means: the module that reads one contributes it as a section, and its default applies to a client without it.

## Offers
- `find` (id → client or none) and `authenticate` (request → client or a typed refusal, never null); both throw unavailable when a source is unavailable.
- An authenticated answer carries the challenges for a later 401 to that client: its method's, or every method's when its method has none.
- `methods` names the usable authentication methods, built in and contributed; `signingAlgorithms` names the algorithms they take signed credentials in.
- A client gives its metadata by section, and says whether the operator registered it or another source named it.
- Extension point `authMethods`: a method names its challenge for a refusal and its signing algorithms, and may say a request carries its credentials malformed.
- Extension points `clientSources` and `metadataSections`; a section may give `checkAtBoot`, which takes a registered client's value of that section after the schema, and the client that holds it, and may give a reason to refuse boot.
- Operator section `registered`: a list of `id`, `kind` (`public` or `confidential`), `method` and `sections` (values by section name); built-in section `client-secret` holds `hash`, a bcrypt or scrypt hash in the forms `secret-hash` reads.
- `./testing`: test clients and configuration builders.

## Invariants
- A request uses one authentication method: two or more are refused first, then credentials a method finds malformed, both before any lookup.
- `none` is the method only when no other method claims the request; an Authorization header no method reads claims nothing.
- A Basic header is malformed unless it is canonical base64 of UTF-8 that decodes to a non-empty id and secret; a `client_id` in the body beside it must name the same client, or the credentials are bad.
- A `client_secret` is malformed unless one non-empty `client_id` is sent once beside it; a `client_id` alone is malformed when sent twice or not as a string, and no credentials when empty.
- `client_secret_post` and `none` read `client_id` and `client_secret` from a form or JSON body, where a value that is not a string still counts as sent.
- A registered client wins over the same id from another source.
- A record failing any section check is refused as a whole; a source's record is also refused unless it passes the registered rule, names a known method and carries the id asked, and when reading it throws.
- An id that is empty, over 256 UTF-16 code units, with a lone surrogate, or with a C0, DEL, C1, U+2028, U+2029 or BOM character is unknown, and no source is asked; registered, it refuses boot.
- `checkAtBoot` sees each registered client that carries the section, and never a source's client, which the section's owner checks at request time.
- A `checkAtBoot` reason refuses boot at `clients.registered.<i>.sections.<name>`, naming the client id and the section; it is attached unchanged, so it never holds a configuration value.
- A secret is checked through `secret-hash`, with decoys of the registered hashes' work; boot refuses a registered `hash` it cannot read (plain text included) or a secret method's client with none, and a source's such secret matches nothing.
- A client's existence is not secret, since its id shows outside: an unknown client, an invalid record and another method's client are refused at once, with no secret check.

## Depends on
- `kernel`, `http`, `secret-hash`

## Vocabulary
- client: an id, a kind (public or confidential), an authentication method, and metadata by section.
- source: where client records come from; registration is built in, and others contribute to `clientSources`.
