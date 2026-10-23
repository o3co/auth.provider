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
				...(c.keys ? { "client-assertion": { keys: c.keys } } : {}),
				...(c.jwksUri ? { "client-assertion": { "jwks-uri": c.jwksUri } } : {}),
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
	const keySets = [
		...part.clients.flatMap((c) => (c.jwksUri ? [new URL(c.jwksUri)] : [])),
		...linked.map((i) => new URL(i.linked.keysUrl)),
	];
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
							...(linked.length > 0
								? {
										"internal-hosts": [
											...new Set(linked.map((i) => new URL(i.linked.keysUrl).hostname)),
										],
									}
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
			...(part.jwtBearer
				? {
						"jwt-bearer": {
							issuers: part.jwtBearer.issuers.map((i) =>
								"linked" in i
									? { issuer: i.issuer, subject: "linked", upstream: i.linked.upstream }
									: {
											issuer: i.issuer,
											subject: "as-is",
											keys: [{ alg: i.alg, "public-key": i.publicPem }],
										},
							),
						},
					}
				: {}),
			...(linked[0]
				? {
						"signer-keys-http": { issuer: linked[0].issuer, "keys-url": linked[0].linked.keysUrl },
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
