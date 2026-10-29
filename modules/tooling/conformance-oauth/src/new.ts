import { randomBytes, scryptSync } from "node:crypto";
import { type AreaScene, type NewPart, onNew } from "@mod/conformance";
import { type ClientScene, type OauthPart, oauthArea } from "./area.ts";

/** A client's logout fields, as rp-logout's section names them; a field left out is left out. */
const logoutSection = (logout: NonNullable<ClientScene["logout"]>) =>
	Object.fromEntries(
		Object.entries({
			"post-logout-redirect-uris": logout.postLogoutRedirectUris,
			"frontchannel-logout-uri": logout.frontchannelLogoutUri,
			"frontchannel-logout-session-required": logout.frontchannelLogoutSessionRequired,
			"backchannel-logout-uri": logout.backchannelLogoutUri,
			"backchannel-logout-session-required": logout.backchannelLogoutSessionRequired,
		}).filter(([, value]) => value !== undefined),
	);

const unpadded = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");

/** The hash the new system keeps a secret as: the one given, or a scrypt hash at the cheapest work. */
function hashOf(c: ClientScene): string | undefined {
	if (c.secretHash !== undefined || c.secret === undefined) return c.secretHash;
	const salt = randomBytes(16);
	const key = scryptSync(c.secret, salt, 32, { N: 1024, r: 8, p: 1 });
	return `$scrypt$ln=10,r=8,p=1$${unpadded(salt)}$${unpadded(key)}`;
}

function clientsSection(part: OauthPart): Record<string, unknown> {
	return {
		registered: part.clients.map((c) => ({
			id: c.id,
			kind: c.kind,
			method: c.method,
			sections: {
				"client-secret": c.secret || c.secretHash ? { hash: hashOf(c) } : {},
				"client-allowance": {
					grants: c.grants,
					scopes: c.scopes,
					...(c.defaultScopes ? { "default-scopes": c.defaultScopes } : {}),
					audiences: c.audiences ?? [],
				},
				...(c.bindingRequired
					? {
							"sender-binding": {
								required: true,
								...(c.bindingKinds ? { kinds: c.bindingKinds } : {}),
							},
						}
					: {}),
				...(c.keys || c.jwksUri
					? {
							"client-assertion": {
								...(c.keys ? { keys: c.keys } : {}),
								...(c.jwksUri ? { "jwks-uri": c.jwksUri } : {}),
								...(c.looseAudience ? { "accept-loose-audience": true } : {}),
							},
						}
					: {}),
				// A client that receives authorization answers is set up for the code flow.
				...(c.redirectUris
					? {
							authorize: { "redirect-uris": c.redirectUris },
							consent: { "first-party": c.firstParty ?? false },
						}
					: {}),
				...(c.upstreamTokens
					? {
							"federation-tokens": {
								receives: true,
								"post-logout-redirect-uris": c.upstreamTokens.postLogoutRedirectUris,
							},
						}
					: {}),
				...(c.federationGrants
					? {
							"federation-grants": {
								connections: c.federationGrants.connections,
								"return-uris": c.federationGrants.returnUris,
							},
						}
					: {}),
				...(c.logout ? { "rp-logout": logoutSection(c.logout) } : {}),
			},
		})),
	};
}

function setUp(part: OauthPart, scene: AreaScene): NewPart {
	const assertions = part.clients.some((c) => c.method === "private_key_jwt");
	const linked = part.jwtBearer
		? part.jwtBearer.issuers.flatMap((i) => ("linked" in i ? [i] : []))
		: [];
	const ledgered = part.jwtBearer ? part.jwtBearer.issuers.filter((i) => i.jtiLedger) : [];
	const ledgerUrls = ledgered.flatMap((i) =>
		i.jtiLedger ? [new URL(i.jtiLedger.consumeUrl)] : [],
	);
	const keySets = [
		...part.clients.flatMap((c) => (c.jwksUri ? [new URL(c.jwksUri)] : [])),
		...linked.map((i) => new URL(i.linked.keysUrl)),
		...ledgerUrls,
	];
	// The operator's own ledgers, each reached at its private address as an internal destination.
	const internal = [...linked.map((i) => new URL(i.linked.keysUrl)), ...ledgerUrls];
	return {
		modules: [
			"@mod/clients",
			"@mod/issuer",
			"@mod/sender-binding",
			"@mod/tokens",
			"@mod/token-endpoint",
			// The client credentials grant is a module of its own: composed where a client is allowed it.
			...(part.clients.some((c) => c.grants.includes("client_credentials"))
				? ["@mod/client-credentials"]
				: []),
			"@mod/client-allowance",
			// The token endpoint and token-control limit requests per source.
			"@mod/rate-limit",
			...(part.jwtBearer ? ["@mod/jwt-bearer"] : []),
			...(linked.length > 0 ? ["@mod/signer-keys-http", "@mod/jwt-bearer-users"] : []),
			...(ledgered.length > 0 ? ["@mod/jti-ledger-http"] : []),
			...(part.introspection || part.revocation ? ["@mod/token-control"] : []),
			...(part.dpop ? ["@mod/dpop"] : []),
			...(part.resourceIndicators ? ["@mod/resource-indicators"] : []),
			...(part.discovery ? ["@mod/discovery"] : []),
			...(part.verifiedEmail ? ["@mod/verified-email"] : []),
			...(assertions ? ["@mod/client-assertion"] : []),
			// Client assertions and JWT bearer grants are checked by external-jwt, which reaches out through outbound.
			...(assertions || part.jwtBearer ? ["@mod/external-jwt", "@mod/outbound"] : []),
			// Revoking a subject reaches its tokens; tokens refuses to start without that check.
			"@mod/subject-revocation",
		],
		without: [
			...(part.authorize === false ? ["@mod/authorize"] : []),
			...(part.dpop === false ? ["@mod/dpop"] : []),
			...(part.jwtBearer === false ? ["@mod/jwt-bearer"] : []),
			...(part.resourceIndicators === false ? ["@mod/resource-indicators"] : []),
		],
		store: "volatile" as const,
		...(part.revocation ? {} : { fallback: { tokens: { revocation: "unsupported" } } }),
		config: {
			// A key set a client publishes on loopback is reached over plain http at that host and port alone.
			...(keySets.length > 0
				? {
						outbound: {
							allow: [...new Set(keySets.map((url) => url.hostname))],
							"plain-loopback": [...new Set(keySets.map((url) => url.host))],
							...(internal.length > 0
								? { "internal-hosts": [...new Set(internal.map((url) => url.hostname))] }
								: {}),
						},
					}
				: {}),
			// Where the store fails, requests are let by uncounted, so the scene reaches the endpoint itself.
			...(scene.storeFaults
				? { "rate-limit": { "fail-mode": part.rateLimitWhileStoreFails ?? "open" } }
				: {}),
			// The deployment is reached at the issuer's origin; what it tells about itself starts there.
			http: { "public-origin": new URL(part.issuer).origin },
			issuer: { url: part.issuer },
			...(part.revocation ? { tokens: { revocation: "denylist" } } : {}),
			clients: clientsSection(part),
			// Nonces asked at the token endpoint, under a scene's own key: 32 bytes, base64.
			...(part.dpopNonce
				? {
						dpop: {
							nonce: {
								required: "as",
								secret: Buffer.from("conformance dpop nonce key, 32 b").toString("base64"),
							},
						},
					}
				: {}),
			...(part.jwtBearer
				? {
						"jwt-bearer": {
							issuers: part.jwtBearer.issuers.map((i) => ({
								...("linked" in i
									? {
											issuer: i.issuer,
											subject: "linked",
											upstream: i.linked.upstream,
											...(i.linked.thumbprint ? { "subject-is-key-thumbprint": true } : {}),
											...(i.linked.selfIssuedPrefix
												? { "self-issued-prefix": i.linked.selfIssuedPrefix }
												: {}),
										}
									: {
											issuer: i.issuer,
											subject: "as-is",
											keys: [{ alg: i.alg, "public-key": i.publicPem }],
											// A scene's issuer is one organisation's: with no conditions, it takes any subject.
											...(i.conditions ? {} : { "accept-any-subject": true }),
										}),
								...(i.conditions ? { conditions: i.conditions } : {}),
								...(i.ceiling ? { ceiling: i.ceiling } : {}),
								...(i.profile ? { profile: i.profile } : {}),
								...(i.client ? { client: i.client } : {}),
							})),
						},
					}
				: {}),
			...(linked[0]
				? {
						"signer-keys-http": { issuer: linked[0].issuer, "keys-url": linked[0].linked.keysUrl },
					}
				: {}),
			...(ledgered[0]?.jtiLedger
				? {
						"jti-ledger-http": {
							issuer: ledgered[0].issuer,
							"consume-url": ledgered[0].jtiLedger.consumeUrl,
							credential: ledgered[0].jtiLedger.credential,
							...(ledgered[0].jtiLedger.credentialHeader
								? { "credential-header": ledgered[0].jtiLedger.credentialHeader }
								: {}),
						},
					}
				: {}),
		},
	};
}

const unvouched =
	"a grant without a session on an app with a user ledger and verified-email: no source can vouch for the subject's email";

onNew(oauthArea, setUp, (part, scene, modules) =>
	part.jwtBearer && ["@mod/users-http", "@mod/verified-email"].every((m) => modules.includes(m))
		? { leaveOut: unvouched }
		: setUp(part, scene),
);
