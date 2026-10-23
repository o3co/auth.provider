# Owner map

Look things up in this table instead of searching for where they go. The owner decides where anything not in the table goes.
What each module contains is described by that module's contract card (each module's README).

| Concern | Kind of ownership | Owner |
|---|---|---|
| Generic rules for module definitions, contracts, extension points, and contributions | contract | kernel |
| Loading configuration sections and boot refusal | contract | kernel |
| Lifecycle (start, drain, stop) | contract | kernel |
| Declaration of multi-instance safety, and the deployment shape | contract / setting | kernel |
| "Unavailable" | vocabulary | kernel |
| Clock, randomness, logging | contract | kernel |
| Log levels and the operator's level, and the sinks log lines go to | contract / extension point / setting | kernel |
| The stdout log sink (each log line as one JSON line) | contract implementation | log-stdout |
| Readiness: running the probes under a deadline and answering ready or unready | contract / extension point | kernel |
| What a readiness probe checks (one per connection) | contribution | the module holding the connection |
| Recording audit events, and the receivers they go to | contract / extension point kind / setting | audit |
| The HTTP audit receiver (each event posted to the operator's URL) | contract implementation / setting | audit-http |
| The stdout audit receiver (each event as one JSON line) | contract implementation | audit-stdout |
| Each audit event kind and its attributes | vocabulary | the module that emits it |
| Counters, histograms and gauges (instruments), their counts within the declared label values, and reading them, gauges when sampled | contract / extension point | metrics |
| Each instrument's name, labels and what it counts | vocabulary | the module that emits it |
| Publishing the counts and the process defaults as Prometheus text, and the scrape route's path | contract implementation / setting | metrics-prometheus |
| Each module's settings | setting | that module |
| Explicit acknowledgment of using something despite the risk | setting | the module that requires it |
| HTTP routes | plug-in point | http |
| The readiness route (`GET /readyz`) and how long it waits | contract / setting | http-ops |
| The liveness route (`GET /_healthcheck`), and timing each request | contract | http-ops |
| Each request's end (`requestEnds`) | extension point | http |
| Route policies (making one, a route's use of one, applying them before the handler) | extension point kind | http |
| A route taking cross-origin requests (its declaration), and the origins allowed | contract / setting | http |
| The security headers on every answer, and what a page declares it loads (the frames and scripts its policy allows) | contract | http |
| Trusted proxies | setting | http |
| Request source | vocabulary | request-source |
| The client's certificate a trusted proxy forwards, the forms it is read in, and whether the operator named where it is forwarded | vocabulary / contract | client-certificate |
| Where a trusted proxy forwards the client's certificate | setting | http |
| Public origin | setting | http |
| Building and reading cookies | contract | cookies |
| What a configured URL may hold (the schema part modules take theirs by) | contract | url-setting |
| When a section's own check of the URLs it holds may read them (once every one parses), and putting what the check answers at its key | contract | url-setting |
| What a module's check of a URL says, such as an outbound refusal | vocabulary | the module that checks |
| Received values: a name's single value, and the names repeated | vocabulary | http |
| Signing, verification, publishing public keys | contract | keys |
| Sending outbound HTTP requests, and the operator's section `outbound` | contract / setting | outbound |
| Where outbound requests may go: the destination policy, its boot questions and host lists | contract / setting | outbound-policy |
| What an IP address reaches by its kind: special-purpose, private, loopback | contract | address-reach |
| Fetching signed material | contract | outbound |
| Which signed material is admitted (plain http from the named hosts) and its size cap | contract / setting | outbound-policy |
| Which destinations a feature reaches | setting | the module that sends the request |
| Rate limiting, lockout | contract | rate-limit |
| Limiting attempts per source on a route | policy | rate-limit |
| Limiting requests per source on a route | policy | rate-limit |
| Limit budgets and key names | setting / vocabulary | the module that calls the limit |
| Sealing at rest (keyring) | contract / setting | seal |
| Checking a secret against a stored hash (bcrypt, scrypt), with the same work when there is none to check | contract | secret-hash |
| The rule for a name a user gives something that a page shows back as it is (a label) | contract | labels |
| Sending mail (one address per send), preparing a message for a sender | contract | mail |
| Mail purposes and mail templates | extension point kind | mail |
| The logging-only mail sender | contract implementation / setting | mail |
| The SMTP mail sender (one connection per send to the operator's relay, securing it, reading its answers) | contract implementation / setting | mail-smtp |
| Each mail purpose | vocabulary | the module that sends that mail |
| The wording of each purpose's mail | contribution | the module that contributes the template |
| Basic storage operations | contract | store |
| Space declarations | extension point kind | store |
| Version, store clock, partition, guarantee, deadline, idempotency marker | vocabulary | store |
| Keyed records (also under a secret), deferred work and keyed sets | implementation | records |
| Place (where records are kept: the store and space a wiring gives) | vocabulary | records |
| Checking JWTs signed by outside keys (header, key choice, signature, times, expected issuer, audience and subject), and fetching key sets | contract | external-jwt |
| How large a feature's deferred work may grow | setting | the per-owner modules in templates |
| Wiring a feature's store interface to a capability's implementation | wiring | the per-owner modules in templates |
| Wiring code-grant's store interface to records | wiring | code-grant-store |
| Wiring session-lifecycle's store interfaces to records | wiring | session-store |
| Wiring refresh's store interfaces to records | wiring | refresh-store |
| Wiring reauth's store interface to records | wiring | authorize-store |
| Wiring client-assertion's store interface to records | wiring | client-assertion-store |
| Wiring device-grant's store interfaces to records | wiring | device-grant-store |
| Wiring dpop's store interface to records | wiring | dpop-store |
| Wiring tokens' store interface to records | wiring | tokens-store |
| Wiring upstream-round-trip's store interface to records under a secret | wiring | upstream-round-trip-store |
| Wiring upstream-handoff's store interface to records under a secret | wiring | upstream-handoff-store |
| Wiring subject-revocation's store interface to records | wiring | subject-revocation-store |
| Wiring consent's store interfaces to records | wiring | consent-store |
| Wiring session-tokens' store interfaces to records' keyed sets, records and deferred work | wiring | session-tokens-store |
| Wiring mfa's store interface to records | wiring | mfa-store |
| Wiring mfa-flows' store interface to records | wiring | mfa-flows-store |
| Wiring users' store interfaces to records | wiring | users-store |
| Wiring webauthn's store interfaces to records | wiring | webauthn-store |
| Wiring federation-tokens' store interfaces to records | wiring | federation-tokens-store |
| Wiring federation-grants' store interfaces to records' records, records under a secret and keyed sets | wiring | federation-grants-store |
| Wiring rp-logout's store interfaces to records | wiring | rp-logout-store |
| What a feature needs from the store, and its records' contents | contract / vocabulary | the feature that defines the store interface |
| Space names, and the guarantees a space declares for those needs | vocabulary / setting | the wiring that declares the space |
| Redis implementation of store | contract implementation / setting | redis |
| Verifying and looking up users, from the settings or one contributed user ledger | contract | users |
| Linking with upstream identities (written links, the settings' fixed ones), looking up a subject from an upstream identity | contract | users |
| A user's verified contacts, and the claimed ones the settings or the ledger state | contract / data | users |
| User ledger, upstream identity, link, verified contact, claimed contact | vocabulary | users |
| The names and value types of user attributes (the OIDC claim names), and a subject's shape | contract / vocabulary | users |
| The HTTP user ledger (verifying passwords at the operator's URL), its request shape and credential | contribution / setting | users-http |
| Logging in through an upstream IdP (start and callback) | contract | federation |
| Linking an upstream identity to the account a browser is logged in as (start and callback) | contract | federation |
| What an opened upstream is to the provider: its authorization URL, code exchange and what its login says | contract | upstreams |
| Opening the configured IdPs through their types, as `upstreams`' default | contract implementation | federation |
| One authorization round trip to an upstream: its state, nonce, verifier and cookie, kept and taken once at its callback | contract | upstream-round-trip |
| Handing a login's upstream tokens to the receivers once its session opens, a held login's kept sealed until then, and a link's join | contract | upstream-handoff |
| Upstream IdP types | extension point kind | upstreams |
| Receiving the upstream tokens of a login once its session opens, or once a link joins it | extension point kind | upstreams |
| An upstream's refresh, end of session and offline delegation, by IdP name | contract | upstreams |
| What IdP types share as OAuth clients of an upstream: the client's credentials, endpoint and scope settings, the authorization request, its Basic authentication, reading its answers and refreshes, checking an OpenID Connect id_token and its profile, the end-session URL | contract | upstream-client |
| Generic OpenID Connect upstreams | contribution / setting | idp-oidc |
| GitHub upstreams | contribution / setting | idp-github |
| Google upstreams | contribution / setting | idp-google |
| Apple upstreams | contribution / setting | idp-apple |
| Keeping a federation login's upstream tokens, handing them to receiving clients, logging a session out of one upstream, and the end of session of a session's first upstream | contract / setting | federation-tokens |
| Receiving upstream tokens, returns after an upstream logout (client metadata fields) | vocabulary / setting | federation-tokens |
| Holding upstream credentials for clients apart from sessions: intents, the user's connection, the upstream token, status, renewal, revocation | contract / setting | federation-grants |
| The connections a client may ask for, where its browser is sent back (client metadata fields) | vocabulary / setting | federation-grants |
| The IdPs, their types and settings, and how each one's amr maps to ours | setting | federation |
| Looking up and authenticating clients | contract | clients |
| Client authentication methods | extension point kind | clients |
| `private_key_jwt` (client assertions), the client's keys (client metadata field) | contribution / vocabulary | client-assertion |
| Client sources | extension point kind | clients |
| Clients whose id is a URL: fetching and judging the metadata document there, building its record from the sections' copies, keeping it, the ceiling they are allowed within | contribution / setting | clients-cimd |
| Client metadata sections | extension point kind | clients |
| Checking a client record as a source's is held (`checkRecord`) | contract | clients |
| The clients the operator registered, in the settings' order (`registered`) | contract | clients |
| Copying a section from a client's metadata document (`documentCopies`, `DocumentSource`) | extension point kind | client-documents |
| Each section's copy from a client's metadata document | contribution | the module that contributes that section |
| Each client metadata field | vocabulary | the module that reads that field |
| Allowed grants, allowed scopes and audiences (client metadata fields), and what a client may be issued and may see | vocabulary / setting / contract | client-allowance |
| The audience a request asks for: the one rule (none reads nothing), asked with each issuance's default and ceiling | extension point kind / contract | grants |
| Resource indicators (RFC 8707): reading `resource` and narrowing the audience issued to it | contribution | resource-indicators |
| Redirect URIs (a client metadata field), the rule for URIs a client may register to be sent back to, and how a given one matches | vocabulary / setting / contract | redirect-uris |
| PKCE required of every client by S256 | contract | authorize |
| Paths to return to after login | extension point kind | login-gates |
| Where a login may return (listed targets, the check) | contract / setting | login-gates |
| first-party, and the name, page and verified host the consent page shows (client metadata fields) | vocabulary / setting | consent |
| Subject revocation boundaries (`sessions`, `delegations`) | contract / vocabulary | subject-revocation |
| Comparison against a revocation boundary | contract | subject-revocation |
| Work that follows a recorded revocation (followers) | extension point kind | subject-revocation |
| Sessions' contract, entry | contract | session |
| Session records, lifecycle | contract implementation / setting | session-lifecycle |
| Session handle, and looking up a request's session | contract / vocabulary | session |
| Entry requirements, and the one order they are asked in | extension point kind | session-requirements |
| The seams an implementation asks the entry requirements and calls the participants through | extension point kind | session |
| Raising authentication (step-up) and rotating the cookie secret | contract | session |
| Login completion gates, and resuming a held login | extension point kind / contract | login-gates |
| Telling the caller that a held login it asked for has opened | extension point kind | login-gates |
| Declarations of the amr values this deployment can produce, and judging whether they can be produced | extension point kind / contract | login-gates |
| Participants when a session closes, and the one order they are called in | extension point kind | session-participants |
| Each subject's live sessions, and closing them when the subject is revoked | contract | session |
| Closing a revoked subject's live sessions (a follower of subject-revocation) | contribution | session-lifecycle |
| Authentication context | vocabulary | session |
| The attributes a login gives (the named set, their caps), and the names of their sources | contract / vocabulary | login-attributes |
| Keeping a login's attributes with the session under their source | contract | session |
| Mapping a login's values to the named set (its source is named by login-attributes) | vocabulary | the login that passes them |
| A subject's attributes from one source (users when it answers for the subject, else the session's login), the name of that source, and whether users vouches for them | contract / vocabulary | subject-attributes |
| Each amr value, and the declaration that it can be produced | vocabulary | the module that supplies that value |
| CSRF checks on a route | policy | csrf |
| Issuing, verifying, revoking access tokens | contract | tokens |
| issuer | contract / setting | issuer |
| scope, audience, actor | vocabulary | tokens |
| Records of access tokens issued per session, cleaning them up when the session closes, the link between an access token and its session | contract | session-tokens |
| Recording each access token issued from a session, as `grants`' session issuances tell of it | contribution | session-tokens |
| A logout a client starts, its returns, the front-channel page and back-channel notices, the clients of each session (client metadata fields, routes, data) | contract / setting / data | rp-logout |
| Ending the upstream session before a logout a client starts returns | extension point kind | rp-logout |
| Sending a client's logout on to the session's upstream | contribution | rp-logout-federation |
| Refresh tokens and families (rotation, reuse detection, revocation), the link between a family and its session, the family an access token belongs to | contract | refresh |
| The refresh grant | grant contribution | refresh |
| The JWT bearer grant (RFC 7523) and its trusted issuers, their keys or key sets | grant contribution / setting | jwt-bearer |
| Resolving a linked JWT bearer signer's subject through users, and declaring the linked issuers' IdP names | contribution | jwt-bearer-users |
| One issuer's JWT bearer signer keys, asked of the operator's HTTP ledger on every assertion, its request shape and credential | contribution / setting | signer-keys-http |
| The token exchange grant (RFC 8693), the verifiers of the token types it exchanges, the actor chain | grant contribution / extension point kind / setting | token-exchange |
| Verifying one token type for exchange | contribution | the module that verifies that type |
| Verifying Apple's and Google's id_tokens for exchange, which client of this provider may exchange each app's id_token, and taking each once | contribution / setting / data | exchange-id-tokens |
| The session grant: an access token for the user of the browser's session, recorded to that session | grant contribution | session-grant |
| The client credentials grant | grant contribution | client-credentials |
| Sender binding (binding kinds, reading a request's binding, the shape of a binding), admitting a request presenting a token at a resource | extension point kind / contract | sender-binding |
| Certificate-bound tokens: the `x5t#S256` binding kind, certificate path validation and revocation checking, trust anchors | contribution / setting | mtls |
| Extra checks added to access token verification | extension point kind | tokens |
| The check of subject revocation on access tokens, and stating there is none | extension point kind / setting | tokens |
| Checking access tokens against the subject revocation boundary | contribution | subject-tokens |
| Issuance policy | plug-in point | tokens |
| Refusing an access token to a subject whose email users has not stated verified | issuance policy contribution | verified-email |
| grant | extension point kind | grants |
| The index of first-party grants: each grant type name and the module that serves it, as words only, never that module's contract | contract | grants |
| Telling of each access token issued from a session (session issuances) | extension point kind | grants |
| Shape of OAuth error responses | contract | token-endpoint |
| Refusing boot for a grant a registered client is allowed that no composed module serves | contract | token-endpoint |
| grant type names | vocabulary | the module that supplies that grant |
| Kinds of revocable tokens | extension point kind | token-control |
| Device Authorization Grant (device authorization, the verification interface, the device code grant) | contract / setting | device-grant |
| Authorization endpoint, steering to the raise (step-up) screen | contract / setting | authorize |
| Re-authentication requests: records asked for one authorization request, taken once, and whether a login is fresh enough | contract | reauth |
| The acr table, and judging which acr values are known and which are satisfied | contract / setting | acr |
| acr table entries | extension point kind | acr |
| Contributed acr names and the amr values that satisfy them | vocabulary | the module that contributes that entry |
| Recording and redeeming authorization codes, code revocation | contract / setting | code-grant |
| ID token producers | extension point kind | code-grant |
| Additions issued with the redemption response | extension point kind | code-grant |
| Clients told of each code redeemed in a session | extension point kind | code-grant |
| Consent records | contract | consent |
| ID token contents (a contribution to code-grant's extension point), claim scope | vocabulary | oidc |
| The claim table (the claims each scope releases), and the claims released for a subject and scope | contract | oidc |
| Judging an ID token given back as a hint | contract | oidc |
| OpenID Connect's userinfo: an access token's subject, and its session's claims while that session is open | route | userinfo |
| Authorization server metadata items (what this server names itself by) | extension point kind | issuer |
| Each metadata item | vocabulary | the module that contributes that item |
| Building and publishing the discovery document | contract | discovery |
| Second factor kinds, with the types they take and give, and the amr a second factor's proof adds | extension point kind / vocabulary | mfa-extensions |
| Steps that prove a factor at login | extension point kind | mfa |
| A user's factor records, and the decisions made over them (provided as mfa-reading's, mfa-binding's and mfa-managing's contracts) | data | mfa |
| Reading a user's factors and proving one, and the words the factor contracts share (`Shown`, `Fence`) | contract / vocabulary | mfa-reading |
| Binding a new second factor: beginning it, its first proof, writing it | contract | mfa-binding |
| Managing a user's factors: naming, removing, clearing them, the recovery codes, the fence | contract | mfa-managing |
| Second factor transactions, contributions to the login completion gate and to step-up, the enrollment routes and their seam, lockout numbers | contract / setting / data | mfa-flows |
| Binding a new second factor: enrollment, its binding proof, the recovery codes shown | contribution | mfa-enrollment |
| An operator's reset of a subject's second factors | contract | mfa-reset |
| A subject's own release of their second-factor lockout, after a proof guessing cannot beat | route | mfa-flows |
| A session's management of its own factors (listing, naming and removing them, reissuing recovery codes), and its request budget | route / setting | mfa-management |
| Each second factor kind | contribution | the module that contributes that kind |
| Proofs asked before a first second factor, and when they are asked | extension point kind / contract / setting | mfa-binding-proof |
| What `begin` asks before a subject's first counting factor | extension point kind | mfa-extensions |
| The enrollment witness: who remembers, apart from mfa's store, that a subject holds a counting factor, and its promises | extension point kind / contract | mfa-witness |
| The enrollment witness kept at the operator's HTTP ledger, its request shape, deadline and credential | contribution / setting | mfa-witness-http |
| Keeping the enrollment witness in line with mfa's counting factors, and filling a missing mark | contribution / contract | mfa-witnessing |
| WebAuthn ceremonies (options and when their challenge ends, verifying responses, the signature count, the user handle) | contract | webauthn |
| Passkeys (each subject's user handle and credentials), assertions by them, registering them for a subject, reading a credential and making a user handle | contract / setting / data | webauthn |
| Registering passkeys from a session (the registration routes), and their request budget | route / setting | passkey-registration |
| Logging in with a passkey (the grant `urn:o3co:oauth:grant-type:webauthn`, its request options), and the amr it gives | grant contribution / contract / setting | webauthn-login |
| WebAuthn as a second factor (the subject's user handle for it, its amr, the name an authenticator shows) | contribution / setting | mfa-webauthn |
| A code by mail as a second factor, how a code is mailed to the account's address, and the mail purposes of both below | contribution / setting / contract | mfa-email |
| The proof of the account's address before a first binding (`account-email`), by mfa-email's rules | contribution | mfa-email-proof |
| The wording of mfa-email's mails, which a deployment replaces | contribution | mfa-email-wording |
| Budget numbers and invariant checks | setting | guard |
| Kind names, their order, and which way a dependency between kinds may point | vocabulary / contract | kinds |
| The checks each kind gets | setting | guard |
| Conformance test base | contract | conformance |
| Running each pattern's conformance areas on its app, and leaving out as `not-in-pattern` the scenes it cannot hold | contract | conformance |
| Starting the legacy build, and registering legacy set-ups | contract | conformance-legacy |
| Each area's scene terms, scenes, set-ups for legacy and new | vocabulary / contribution | each area's conformance module |
| Repo layout (where packages go) | setting | the workspace definition |
| Generating a project: the command, the plan, and where the packages come from (the workspace or a bundle's index) | contract | create-app |
| A generated project's files (a listed app, or a deployment of full or a pattern: the module list, configuration gathered from the modules' fragments, env and local examples, Dockerfile, README) | template | app-output |
| The patterns: each one's use, selection, conformance areas and card, and the operator's choice over them | template | create-app (`patterns`) |
| The generated references: the configuration reference, each package's `reference.conf`, the audit event reference and the route reference | contract | references |
| What is composed together by default (a feature's wiring, the bridges between features), a selection's composition (what it needs to run, each axis's adapter), the full template, and the features that opt in | contract | combinations |
| Declaring that a feature's store interfaces must be wired (`storeWiring` in the feature's package.json, checked by guard) | setting | the feature whose store interfaces must be wired |
| How distribution is bundled | setting | distribution |
