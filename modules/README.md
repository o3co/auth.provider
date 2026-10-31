# Owner map

Look things up in this table instead of searching for where they go. The owner decides where anything not in the table goes.
What each module contains is described by that module's contract card (each module's README).

| Concern | Kind of ownership | Owner |
|---|---|---|
| Generic rules for module definitions, contracts, extension points, and contributions | contract | kernel |
| Loading configuration sections and boot refusal | contract | kernel |
| Reading an app's configuration files into one tree for `assemble`, and the 0.17 variables the environment sets that no file reads | contract | config-files |
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
| The floor of the provider's own TLS connections as a client, the certificate checked among it: the section `tls-options`, its contract and `heldToFloor` | contract / setting | tls-options |
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
| Wiring claims-selection's store interface to records | wiring | claims-selection-store |
| Wiring mfa's store interface to records | wiring | mfa-store |
| Wiring mfa-flows' store interface to records | wiring | mfa-flows-store |
| Wiring users' store interfaces to records | wiring | users-store |
| Wiring passkeys' store interfaces to records | wiring | webauthn-store |
| Wiring federation-tokens' store interfaces to records | wiring | federation-tokens-store |
| Wiring federation-grants' store interfaces to records' records, records under a secret and keyed sets | wiring | federation-grants-store |
| Wiring rp-logout's store interfaces to records | wiring | rp-logout-store |
| Wiring jwt-bearer's store interface to records | wiring | jwt-bearer-store |
| Wiring exchange-id-tokens' store interface to records | wiring | exchange-id-tokens-store |
| What a feature needs from the store, and its records' contents | contract / vocabulary | the feature that defines the store interface |
| Space names, and the guarantees a space declares for those needs | vocabulary / setting | the wiring that declares the space |
| Redis implementation of store | contract implementation / setting | redis |
| Verifying and looking up users, from the settings or one contributed user ledger | contract | users |
| Linking with upstream identities (written links, the settings' fixed ones), looking up a subject from an upstream identity | contract | users |
| A user's verified contacts, and the claimed ones the settings or the ledger state | contract / data | users |
| User ledger, upstream identity, link, verified contact, claimed contact | vocabulary | users |
| The names and value types of user attributes (the OIDC claim names), and a subject's shape | contract / vocabulary | users |
| The HTTP user ledger (verifying passwords at the operator's URL), its request shape and credential | contribution / setting | users-http |
| An outside user ledger's revocation of a subject, received over https with a credential from a listed source, and recorded through subject-revocation | contribution / setting | subject-revocation-http |
| The words of the wire spoken with the operator's HTTP ledgers (the user ledger's and the witness ledgers' calls): bodies, answers' schemas, statuses, the fakes' routes | vocabulary | ledger-wire |
| Logging in through an upstream IdP (start and callback) | contract | federation |
| Linking an upstream identity to the account a browser is logged in as (start and callback) | contract | federation |
| The continuation named `link` of federation's round trip: linking the upstream identity to the browser's account at its request | contribution | federation-link |
| What an opened upstream is to the provider: its authorization URL, code exchange and what its login says | contract | upstreams |
| Opening the configured IdPs through their types, as `upstreams`' default | contract implementation | federation |
| One authorization round trip to an upstream: its state, nonce, verifier and cookie, kept and taken once at its callback | contract | upstream-round-trip |
| Handing a login's upstream tokens to the receivers once its session opens, a held login's kept sealed until then, and a link's join | contract | upstream-handoff |
| The seal a held login's tokens are kept under | extension point kind | upstream-handoff |
| Giving the handoff the composed seal | contribution | upstream-handoff-seal |
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
| Holding upstream credentials for clients apart from sessions: intents and their steps, the browser routes, the upstream token, status, renewal, revocation | contract / setting | federation-grants |
| The browser half of federation grants: the link, the question, the decision and the upstream's callback over federation-grants' intent steps, whose upstream account a callback reached, and its pages and identity check | contribution / setting | federation-grants-connect |
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
| The password login endpoint (verified by users, logged in through login-gates, the time the password was verified as the login's time) | route | login-password |
| The session logout endpoint | route | logout |
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
| Access tokens revoked before their end (the ids kept), and its store interface | data / contract | token-denylist |
| issuer | contract / setting | issuer |
| scope, audience, actor | vocabulary | tokens |
| The claims a grant adds to its access token: their shape, the names reserved, the limits, and the one walker that checks and copies a set | contract / vocabulary | added-claims |
| Records of access tokens issued per session, cleaning them up when the session closes, the link between an access token and its session | contract | session-tokens |
| Recording each access token issued from a session, as `grants`' session issuances tell of it | contribution | session-tokens |
| The claim names a `claims` request releases beyond its scope, by allowance and consent, and their value constraints, kept for the code, the redemption, the refresh family and each access token | contract | claims-selection |
| Judging consent for a selection's names | extension point kind | claims-selection |
| The scope each claim belongs to, from the module releasing claims | extension point kind | claims-selection |
| Pinning a redemption's selection and keeping it for the redeemed token, as `code-grant`'s redemption hooks tell of it | contribution | claims-selection |
| Carrying a token's constraints to a token exchanged from it, as `grants`' token ties | contribution | claims-selection |
| A logout a client starts, its returns, the front-channel page and back-channel notices, the clients of each session (client metadata fields, routes, data) | contract / setting / data | rp-logout |
| Ending the upstream session before a logout a client starts returns | extension point kind | rp-logout |
| Sending a client's logout on to the session's upstream | contribution | rp-logout-federation |
| Refresh tokens and families (rotation, reuse detection, revocation), the link between a family and its session, the family an access token belongs to | contract | refresh |
| The refresh grant | grant contribution | refresh |
| The JWT bearer grant (RFC 7523) and its trusted issuers, their keys or key sets, and the issuers whose assertions it leaves to another module's rules | grant contribution / setting | jwt-bearer |
| Resolving a linked JWT bearer signer's subject through users, and declaring the linked issuers' IdP names | contribution | jwt-bearer-users |
| Taking Apple's and Google's id_tokens as JWT bearer assertions, by exchange-id-tokens' checks | contribution | jwt-bearer-id-tokens |
| One issuer's JWT bearer signer keys, asked of the operator's HTTP ledger on every assertion, its request shape and credential | contribution / setting | signer-keys-http |
| One issuer's JWT bearer assertions used up in the operator's HTTP ledger, shared with other services accepting them, its request shape and credential | contribution / setting | jti-ledger-http |
| The token exchange grant (RFC 8693), the verifiers of the token types it exchanges, the actor chain | grant contribution / extension point kind / setting | token-exchange |
| Verifying one token type for exchange | contribution | the module that verifies that type |
| Verifying Apple's and Google's id_tokens for exchange and for any grant that takes them, which client of this provider each app's id_token is for, and taking each once | contribution / setting / data | exchange-id-tokens |
| The session grant: an access token for the user of the browser's session, recorded to that session | grant contribution | session-grant |
| The client credentials grant | grant contribution | client-credentials |
| Sender binding (binding kinds, reading a request's binding, the shape of a binding), admitting a request presenting a token at a resource | extension point kind / contract | sender-binding |
| DPoP proofs (RFC 9449) as a binding kind, each proof's `jti` spent once | contribution / setting | dpop |
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
| Reading a `claims` request (acr, `sub` values, the claims named beyond the scope) and refusing a `sub` other than the session's | contract | authorize |
| Whether a `claims` request's names and value constraints are taken, and discovery says the parameter is supported (`claims-parameter`) | setting | authorize |
| Judging consent for a claims request's names, as for the scope | contribution | authorize |
| Re-authentication requests: records asked for one authorization request, taken once, and whether a login is fresh enough | contract | reauth |
| The acr table, and judging which acr values are known and which are satisfied | contract / setting | acr |
| acr table entries | extension point kind | acr |
| Contributed acr names and the amr values that satisfy them | vocabulary | the module that contributes that entry |
| The acr a second factor meets, as an entry of acr's table | contribution | mfa-acr |
| Recording and redeeming authorization codes, code revocation | contract / setting | code-grant |
| ID token producers | extension point kind | code-grant |
| Additions issued with the redemption response | extension point kind | code-grant |
| Clients told of each code redeemed in a session | extension point kind | code-grant |
| Hooks pinned with each code redemption and told what it gave | extension point kind | code-grant |
| Consent records | contract | consent |
| ID token contents (a contribution to code-grant's extension point), claim scope | vocabulary | oidc |
| The claim table (the claims each scope releases, and the scope of each claim), and the claims released for a subject, scope and what a request asks beyond it, held to its constraints | contract | oidc |
| Judging an ID token given back as a hint | contract | oidc |
| Each table claim's scope, as `claims-selection`'s table of claim scopes | contribution | oidc |
| OpenID Connect's userinfo: an access token's subject, and its session's claims by its scope and kept selection while that session is open | route | userinfo |
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
| Judging a session against second factors: mfa's entry requirement for using a session and for changing credentials, and whether a second factor was proved recently | contract | mfa-entry |
| Moving a revoked subject's fence in mfa, so no binding begun before a revocation binds once it is complete | contribution | mfa-revocation |
| Binding a new second factor: enrollment, its binding proof, the recovery codes shown | contribution | mfa-enrollment |
| An operator's reset of a subject's second factors | contract | mfa-reset |
| A reset's parts: what a module holds that an operator's reset removes beside the second factors | extension point kind | mfa-reset |
| Removing what a part holds for a subject | contribution | the module contributing that part |
| A subject's own release of their second-factor lockout, after a proof guessing cannot beat | route | mfa-flows |
| A session's management of its own factors (listing, naming and removing them, reissuing recovery codes), and its request budget | route / setting | mfa-management |
| Each second factor kind | contribution | the module that contributes that kind |
| TOTP (RFC 6238) as a second factor kind | contribution | mfa-totp |
| Recovery codes as a second factor kind | contribution | mfa-recovery |
| Proofs asked before a first second factor, and when they are asked | extension point kind / contract / setting | mfa-binding-proof |
| What `begin` asks before a subject's first counting factor | extension point kind | mfa-extensions |
| The enrollment witness: who remembers, apart from mfa's store, that a subject holds a counting factor, and its promises | extension point kind / contract | mfa-witness |
| The enrollment witness kept at the operator's HTTP ledger, its request shape, deadline and credential | contribution / setting | mfa-witness-http |
| The passkey witness: who remembers, apart from passkeys' store, that a subject holds a passkey, and its promises | extension point kind / contract | passkey-witness |
| The passkey witness kept at the operator's HTTP ledger, its request shape, deadline and credential | contribution / setting | passkey-witness-http |
| Keeping the enrollment witness in line with mfa's counting factors, and filling a missing mark | contribution / contract | mfa-witnessing |
| Keeping the passkey witness's mark in line with passkeys, and filling a missing mark (`passkeyBackfill`) | contribution / contract | passkey-witnessing |
| WebAuthn ceremonies (options and when their challenge ends, verifying responses, the signature count, the user handle) | contract | webauthn |
| Passkeys (each subject's user handle and credentials), assertions by them, registering them for a subject, reading a credential and making a user handle | contract / setting / data | passkeys |
| Registering passkeys from a session (the registration routes), and their request budget | route / setting | passkey-registration |
| Logging in with a passkey (the grant `urn:o3co:oauth:grant-type:webauthn`, its request options), and the amr it gives | grant contribution / contract / setting | webauthn-login |
| Logging into a browser session with a passkey (its options and assertion routes), and refusing a password login of a subject holding one where the operator says so | route / contribution / setting | login-passkey |
| An operator's reset of a subject's passkeys, and the passkeys' step of mfa-reset's parts | contract | passkey-reset |
| Having an operator's reset of second factors remove the subject's passkeys too | contribution | mfa-reset-passkeys |
| WebAuthn as a second factor (the subject's user handle for it, its amr, the name an authenticator shows) | contribution / setting | mfa-webauthn |
| A code by mail as a second factor, how a code is mailed to the account's address, and the mail purposes of both below | contribution / setting / contract | mfa-email |
| The proof of the account's address before a first binding (`account-email`), by mfa-email's rules | contribution | mfa-email-proof |
| The wording of mfa-email's mails, which a deployment replaces | contribution | mfa-email-wording |
| Budget numbers and invariant checks | setting | guard |
| Kind names, their order, and which way a dependency between kinds may point | vocabulary / contract | kinds |
| The checks each kind gets | setting | guard |
| Reading the workspace's packages, imports and public surfaces, and the checks of how packages depend on one another and what they import | contract | guard-imports |
| Conformance test base | contract | conformance |
| Running each pattern's conformance areas on its app, and leaving out as `not-in-pattern` the scenes it cannot hold | contract | conformance |
| The local layer that boots a generated app for a test or a conformance run, from each composed module's trial file | contract | trial |
| Running the docker client within a time, and how each of its commands fails, for every package that drives Docker | contract | docker-client |
| An https front before a running app, for a harness's outside party | contract | conformance-front |
| A way out from a harness's app to a party on this machine by its name alone (an HTTP CONNECT proxy on loopback, as `outbound.proxy`) | contract | conformance-tunnel |
| Starting the legacy build, and registering legacy set-ups | contract | conformance-legacy |
| Fake HTTP ledgers for tests and conformance scenes (the user ledger, mfa's and passkeys' witness ledgers) | contract | ledger-fakes |
| The checklist of the specifications' requirements on the authorization server and the ledger of their sources, which tests name which, the checklist report, and whether an accepted difference may be taken | contract / data | spec-checklist |
| Each area's scene terms, scenes, set-ups for legacy and new | vocabulary / contribution | each area's conformance module |
| The scenes of the code flow area (the authorization endpoint, consent, code redemption, refresh, acr, the session grant, a logout the client starts) | vocabulary / contribution | conformance-code |
| The scenes of the device area (RFC 8628) | vocabulary / contribution | conformance-device |
| The scenes of the exchange area (RFC 8693) | vocabulary / contribution | conformance-exchange |
| The scenes of the federation area (logging in through an upstream IdP) | vocabulary / contribution | conformance-federation |
| The scenes of the identity area (password login, logout, the user ledger over HTTP) | vocabulary / contribution | conformance-identity |
| The scenes of the keys area (the public key set, key configuration) | vocabulary / contribution | conformance-keys |
| The scenes of the mTLS area (certificate-bound tokens) | vocabulary / contribution | conformance-mtls |
| The scenes of the OAuth endpoints area (client credentials, introspection, revocation, jwt-bearer, DPoP, the metadata document) | vocabulary / contribution | conformance-oauth |
| The scenes of operations (liveness, readiness, metrics, the log level, the security headers) | vocabulary / contribution | conformance-ops |
| The scenes of the passkey area (registration, login with a passkey) | vocabulary / contribution | conformance-passkey |
| The scenes of the second-factor area | vocabulary / contribution | conformance-second-factor |
| Each recipe's scene, kept from going stale: generating its app, making its requests, writing the exchanges into the recipe | contribution | conformance-recipes |
| Running the provider against independent client libraries, and the differences accepted with each | contract / data | interop-clients |
| Running the OpenID Foundation's conformance suite against the provider, and the expected entries a test's result may take | contract / data | interop-oidf |
| Repo layout (where packages go) | setting | the workspace definition |
| Generating a project: the command, the plan, and where the packages come from (the workspace or a bundle's index) | contract | create-app |
| A generated project's files (a listed app, or a deployment of full or a pattern: the module list, configuration gathered from the modules' fragments, env and local examples, Dockerfile, README) | template | app-output |
| The patterns: each one's use, selection, conformance areas and card, and the operator's choice over them | template | create-app (`patterns`) |
| The generated references: the configuration reference, each package's `reference.conf`, the audit event reference and the route reference | contract | references |
| What is composed together by default (a feature's wiring, the bridges between features), a selection's composition (what it needs to run, each axis's adapter), the full template, and the features that opt in | contract | combinations |
| Declaring that a feature's store interfaces must be wired (`storeWiring` in the feature's package.json, checked by guard) | setting | the feature whose store interfaces must be wired |
| How distribution is bundled | setting | distribution |
| The API site: a release's API built from the shipped bundles, by public name, one dir per minor, and the site's root and list of releases | contract | api-docs |
