/**
 * What the attack surface reference cannot read from what modules declare, written by hand: each
 * entry says why. The reference's tests hold every entry to the workspace (a key, a route, a
 * package or a runbook section that is no more fails), and every key whose name or whose mention in
 * the security model makes it a candidate to be classified here or by the naming rules.
 */
export interface Coverage {
	/** Routes that send the browser elsewhere: where it goes, never through `outbound`. */
	readonly redirects: readonly {
		readonly method: string;
		readonly path: string;
		readonly to: string;
	}[];
	/** Settings that hold a secret, beyond those the naming rule finds. */
	readonly secrets: readonly { readonly key: string; readonly holds: string }[];
	/** Settings the naming rule takes for a secret, and are not. */
	readonly notSecrets: readonly { readonly key: string; readonly why: string }[];
	/** Settings that weaken a guarantee when set, beyond those the naming rule finds, or saying how one it finds does. */
	readonly loosening: readonly { readonly key: string; readonly weakens: string }[];
	/** Settings a candidate by name or by the security model, that weaken none. */
	readonly notLoosening: readonly { readonly key: string; readonly why: string }[];
	/** Settings that name where the provider reaches out to, beyond those the naming rule finds. */
	readonly destinations: readonly { readonly key: string; readonly reaches: string }[];
	/** Settings a candidate by name to name a destination, that name none. */
	readonly notDestinations: readonly { readonly key: string; readonly why: string }[];
	/** What the operator does by hand, by the runbook's section. */
	readonly manualTasks: readonly { readonly anchor: string; readonly what: string }[];
}

export const coverage: Coverage = {
	redirects: [
		{
			method: "GET",
			path: "/oauth/authorize",
			to: "the client's registered `redirect_uri`, or the login and consent pages",
		},
		{ method: "POST", path: "/oauth/authorize", to: "the client's registered `redirect_uri`" },
		{
			method: "GET",
			path: "/oauth/logout",
			to: "the client's registered `post_logout_redirect_uri`, an upstream's end of session, or the deployment's error page",
		},
		{
			method: "POST",
			path: "/oauth/logout",
			to: "the client's registered `post_logout_redirect_uri`, an upstream's end of session, or the deployment's error page",
		},
		{
			method: "POST",
			path: "/oauth/federation/*",
			to: "an upstream's end of session (`federation-tokens`' logout)",
		},
		{
			method: "GET",
			path: "/session/oauth/federation/*",
			to: "the upstream identity provider's authorization endpoint",
		},
		{
			method: "GET",
			path: "/session/oauth/federation/*/callback",
			to: "the login's next step on this provider",
		},
		{
			method: "POST",
			path: "/session/oauth/federation/*/callback",
			to: "the login's next step on this provider",
		},
		{
			method: "GET",
			path: "/session/federation-grants/connect",
			to: "the upstream identity provider's authorization endpoint",
		},
		{
			method: "GET",
			path: "/session/federation-grants/callback/*",
			to: "the client's page the grant names",
		},
	],
	secrets: [
		{ key: "outbound.proxy-authorization", holds: "the credential the outbound proxy asks for" },
		{ key: "redis.url", holds: "the Redis password, where the URL carries one" },
		{ key: "audit-http.authorization", holds: "the credential the audit collector asks for" },
		{
			key: "keys.next.public-key",
			holds: "the next signing key, which may be given as its private PEM",
		},
		{
			key: "keys.previous",
			holds: "a previous signing key, which may be given as its private PEM",
		},
		{
			key: "keys.previous.<i>.public-key",
			holds: "a previous signing key, which may be given as its private PEM",
		},
		{
			key: "users.registered.<i>.password-hash",
			holds: "a registered user's password hash, which a guess can be tried against offline",
		},
		{ key: "seal.previous", holds: "the previous sealing keys" },
	],
	notSecrets: [
		{
			key: "login-passkey.password",
			why: "whether password logins are taken beside passkeys, not a password",
		},
	],
	loosening: [
		{
			key: "mail-smtp.security",
			weakens:
				"`none`: no TLS, so the relay's authentication and the mail go in the clear, to a loopback relay only",
		},
		{
			key: "outbound.allow-any-public",
			weakens: "any public host is reached by name, not only those `outbound.allow` lists",
		},
		{
			key: "outbound.internal-hosts",
			weakens: "URLs of the operator's own configuration reach private addresses at these hosts",
		},
		{
			key: "outbound.plain-internal",
			weakens: "plain http to these pairs, readable and changeable on the way",
		},
		{ key: "outbound.plain-loopback", weakens: "plain http to these loopback pairs" },
		{
			key: "outbound.plain-ipv4",
			weakens: "these pairs' IPv6 answers are neither checked nor used",
		},
		{
			key: "outbound.proxy",
			weakens: "the proxy, not `outbound`, resolves names and checks where they lead",
		},
		{
			key: "federation-grants.keep-on-subject-revocation",
			weakens:
				"an established grant answers only to the `delegations` boundary when a revocation asks to keep delegations",
		},
		{ key: "tokens.revocation", weakens: "`unsupported`: nothing issued can be revoked" },
		{
			key: "mfa-binding-proof.mode",
			weakens: "`never`: a first counting factor binds with no binding proof asked",
		},
		{
			key: "webauthn.top-origins",
			weakens: "each page named may frame a ceremony, in another origin's page",
		},
		{
			key: "mfa-webauthn.user-verification",
			weakens:
				"`discouraged`: the authenticator is not asked to verify its user, so whoever holds it passes",
		},
		{
			key: "passkeys.user-verification",
			weakens:
				"`discouraged`: the authenticator is not asked to verify its user, so whoever holds it passes",
		},
		{
			key: "acr.values",
			weakens:
				"an acr met by a weak amr set: a login with only that is taken for the acr, so a step-up asking it asks no more",
		},
		{
			key: "device-grant.attempts",
			weakens: "raised, up to 100: more guesses at a user code in each window",
		},
		{
			key: "device-grant.attempts-window",
			weakens: "shortened: the guesses `attempts` allows come back sooner",
		},
		{
			key: "login-password.attempts",
			weakens: "raised, up to 100: more password guesses from one source in each window",
		},
		{
			key: "login-password.account-attempts",
			weakens:
				"raised, up to 100: more failed guesses at one identifier before each next one waits",
		},
		{
			key: "login-passkey.attempts",
			weakens: "raised, up to 100: more requests from one source in each window",
		},
		{
			key: "mfa-flows.attempts-per-transaction",
			weakens: "raised, up to 10: more second-factor guesses in one transaction",
		},
		{
			key: "sections.consent.first-party",
			weakens:
				"`true`: that client's users are never asked for consent; taken only for a client the operator registered",
		},
		{
			key: "sections.token-exchange.others-tokens",
			weakens: "`true`: the client may exchange subject and actor tokens that name another client",
		},
		{
			key: "sections.token-exchange.public-exchange",
			weakens: "`true`: the client may exchange while public, authenticating nothing",
		},
		{
			key: "sections.federation-tokens.receives",
			weakens: "`true`: the client is handed its sessions' upstream tokens",
		},
		{
			key: "federation-grants-connect.identity-check",
			weakens: "`none`: a callback whose upstream account another user holds is not refused",
		},
		{
			key: "jwt-bearer.issuers.<i>.client",
			weakens:
				"a request naming no client is taken as this public client, its assertions alone identifying it; warned at boot",
		},
		{
			key: "jwt-bearer.issuers.<i>.self-issued-prefix",
			weakens:
				"any signer whose contributed key's thumbprint follows this prefix in `iss` and `sub` is taken as this issuer",
		},
		{
			key: "mfa-flows.lockout.threshold",
			weakens:
				"raised, with no upper bound: more second-factor guesses before a hold, so past enough no lockout at all",
		},
		{
			key: "mfa-flows.lockout.budget",
			weakens:
				"raised, with no upper bound: more second-factor guesses before a hold, so past enough no lockout at all",
		},
		{
			key: "mfa-flows.lockout.hard-limit",
			weakens:
				"raised, with no upper bound: more second-factor guesses before a hold, so past enough no lockout at all",
		},
		{
			key: "mfa-flows.lockout.backoff",
			weakens:
				"shortened: holds after failed second-factor guesses end sooner, so more guesses go through",
		},
		{
			key: "mfa-flows.lockout.max-backoff",
			weakens:
				"shortened: holds after failed second-factor guesses end sooner, so more guesses go through",
		},
		{
			key: "mfa-flows.lockout.budget-window",
			weakens:
				"shortened: holds after failed second-factor guesses end sooner, so more guesses go through",
		},
		{
			key: "mfa-flows.lockout.memory",
			weakens:
				"shortened: holds after failed second-factor guesses end sooner, so more guesses go through",
		},
		{
			key: "refresh.lifetime",
			weakens:
				"past the default day, up to 365 days: a leaked refresh token family is used that long",
		},
		{
			key: "session-lifecycle.lifetime",
			weakens: "past the default hour, up to 30 days: a session and its cookie are taken that long",
		},
		{
			key: "oidc.id-token-lifetime",
			weakens: "past the default hour: a relying party may take an ID token that long",
		},
		{
			key: "federation-grants.max-lifetime",
			weakens:
				"past the default 30 days, up to 365: a federation grant answers that long from its activation",
		},
		{
			key: "federation-tokens.max-lifetime",
			weakens: "past the default day, up to 365: an upstream's token is taken to live that long",
		},
		{
			key: "external-jwt.key-set-max-age",
			weakens:
				"past the default day, up to 30: a key set is still used that long after its fetch while no new one can be had, a key removed upstream among it",
		},
		{
			key: "client-assertion.max-lifetime",
			weakens: "past the default hour, up to a day: a client assertion is taken that long",
		},
		{
			key: "jwt-bearer.max-assertion-lifetime",
			weakens:
				"past the default hour, up to a day: a jwt-bearer assertion is taken with its `exp` that far ahead, and its `exp` no further from its `iat`",
		},
		{
			key: "federation.idps.<name>.secret-lifetime",
			weakens:
				"past the default five minutes, up to half a year: a signed client secret, if leaked, is used that long",
		},
		{
			key: "device-grant.code-lifetime",
			weakens:
				"past the default ten minutes, up to an hour: a user code can be guessed and a device code used that long",
		},
		{
			key: "exchange-id-tokens.max-age",
			weakens:
				"past the default ten minutes, up to an hour: an older id_token is taken for an exchange",
		},
		{
			key: "tokens.subject-check",
			weakens:
				"`none`: no module checks an access token's subject against its revocations, so a revoked subject's access tokens are taken until they expire",
		},
		{
			key: "token-exchange.max-lifetime",
			weakens:
				"a lifetime a client asks of an exchange (`o3co_expires_in`) is taken up to this, up to a day, past `tokens`' own lifetimes, though never past the subject token's end or its ties'",
		},
		{
			key: "login-passkey.counts-as-mfa",
			weakens:
				"`true` (the default): a passkey login whose user was verified meets a required second factor alone",
		},
		{
			key: "mfa-email.adds-second-factor",
			weakens: "`true`: a code by mail meets a required second factor, so the mailbox does",
		},
		{
			key: "rate-limit.fail-mode",
			weakens:
				"`open`: while the store cannot count, a route's request limit lets every request through",
		},
		{
			key: "redis.durability",
			weakens:
				"`none`: a crash loses the latest writes, spent assertion and proof ids and lockout records among them",
		},
		{
			key: "redis.replication",
			weakens: "`none`: a failover loses writes, confirmed ones too",
		},
		{
			key: "audit.receivers",
			weakens: "`none`: audit events go nowhere, warned at every boot",
		},
		{
			key: "tokens.access-token-lifetime",
			weakens:
				"past the default hour, up to a day: a leaked access token, or one a resource server verifies itself after a revocation, is taken that long",
		},
		{
			key: "mtls.mode",
			weakens: "`self-signed`: any certificate that parses binds, with no revocation",
		},
		{ key: "mtls.revocation.mode", weakens: "`disabled`: no certificate's revocation is checked" },
		{ key: "kernel.environment", weakens: "`development`: plain-http origins and pages are taken" },
		{
			key: "oidc.id-token-alg",
			weakens:
				"other than `RS256`: the metadata lists no `RS256` (OpenID Connect Discovery 1.0 §3), and a relying party that registers no algorithm, so expects `RS256`, gets ID tokens signed with this one",
		},
		{
			key: "dpop.nonce.required",
			weakens: "`never`: no nonce is asked, so a proof made ahead is taken within its window",
		},
		{
			key: "login-passkey.password-exempt-group",
			weakens: "its members keep password logins where passkey holders are refused them",
		},
		{
			key: "federation.idps",
			weakens:
				"each IdP's `upstream-amr` trusts its word for the local amr it maps, `mfa` among them; its `fresh-login-allowance` lets a login that far back count as fresh",
		},
		{
			key: "kernel.deployment",
			weakens:
				"`single`: modules unsafe on several instances (the memory store, mail that only logs) are taken",
		},
		{
			key: "mfa.mode",
			weakens: "below `required`, using a session needs no second factor",
		},
		{
			key: "outbound.resolution",
			weakens:
				"`in-process`: names resolve in the app's own process, not in helpers that take none of its environment",
		},
		{
			key: "clients-cimd.allow",
			weakens: "clients name themselves by a metadata document fetched from these hosts",
		},
		{
			key: "clients-cimd.allow-any-host",
			weakens: "clients name themselves by a metadata document fetched from any host `deny` leaves",
		},
	],
	destinations: [
		{
			key: "jwt-bearer.issuers",
			reaches: "each trusted issuer's `jwks-uri`, where its key set is fetched",
		},
		{ key: "mail-smtp.host", reaches: "the SMTP relay" },
		{ key: "federation.idps.<name>.api", reaches: "a GitHub's API, for the user's profile" },
		{
			key: "federation.idps.<name>.issuer",
			reaches:
				"an IdP's issuer, and for OpenID Connect its discovery document and the endpoints it names",
		},
	],
	notDestinations: [
		{
			key: "jwt-bearer.issuers.<i>.issuer",
			why: "the issuer an assertion's `iss` is matched with, never fetched; its keys come from `jwks-uri`",
		},
		{
			key: "clients-cimd.allow-any-host",
			why: "a switch that names no host: documents are fetched where a client id points",
		},
		{
			key: "federation.idps.<name>.hosted-domains",
			why: "the Google Workspace domains a login must belong to",
		},
		{ key: "http.host", why: "the address the app listens on" },
		{
			key: "sections.consent.host",
			why: "the host a client's source verified, shown on the consent page",
		},
		{
			key: "jwt-bearer.delegated-issuers",
			why: "the `iss` values another module checks; their keys are where that module fixes them (`exchange-id-tokens`, by the kind)",
		},
		{ key: "jti-ledger-http.issuer", why: "the `iss` the ledger answers for, not where it is" },
		{ key: "signer-keys-http.issuer", why: "the `iss` the ledger answers for, not where it is" },
		{
			key: "federation.idps.<name>.discovery",
			why: "whether the issuer's discovery is read; the issuer is the destination",
		},
	],
	notLoosening: [
		{
			key: "sections.sender-binding.required",
			why: "`true` binds every token issued to the client; its default takes bearer tokens, the client's choice as the security model leaves it",
		},
		{
			key: "http.proxy-hops",
			why: "how deep forwarding is followed through trusted proxies: part of naming them",
		},
		{
			key: "outbound.direct-despite-proxy",
			why: "only whether boot goes on while a proxy variable is set; the variables are never read",
		},
		{
			key: "http.headers-timeout",
			why: "a bound the app keeps; the bounds per client are the proxy's, as the security model leaves them",
		},
		{
			key: "http.request-timeout",
			why: "a bound the app keeps; the bounds per client are the proxy's, as the security model leaves them",
		},
		{
			key: "http.max-connections",
			why: "a bound the app keeps; the bounds per client are the proxy's, as the security model leaves them",
		},
		{ key: "authorize.login-page", why: "the deployment's page, which it draws and protects" },
		{ key: "consent.page", why: "the deployment's page, which it draws and protects" },
		{ key: "rp-logout.error-page", why: "the deployment's page, which it draws and protects" },
		{
			key: "outbound.allow",
			why: "the hosts outbound may reach by name at all: the list opens only what it names",
		},
		{
			key: "http.trusted-proxies",
			why: "the peers whose forwarding is believed: a trust assumption the security model states",
		},
	],
	manualTasks: [
		{ anchor: "rotating-the-signing-key", what: "rotating the signing key" },
		{
			anchor: "rotating-the-sealing-key",
			what: "rotating the sealing key, and resealing what the old one sealed",
		},
		{ anchor: "revoking-a-user-from-the-ledger", what: "revoking a user at the ledger" },
		{
			anchor: "second-factors-left-without-their-claim",
			what: "finding and resetting second factors left without their claim",
		},
		{ anchor: "resetting-a-subjects-passkeys", what: "resetting a subject's passkeys" },
		{ anchor: "filling-the-passkey-witnesss-marks", what: "filling the passkey witness's marks" },
		{ anchor: "upgrading", what: "upgrading" },
	],
};
