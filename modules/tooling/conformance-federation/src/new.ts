import { randomBytes } from "node:crypto";
import { type NewPart, onNew, type PatternPart } from "@mod/conformance";
import { type FederationPart, federationArea, type GrantsPart, type IdpScene } from "./area.ts";

/**
 * An IdP's own settings, by the type that serves it on the new target: its type's endpoints at the
 * scene's `issuer` where the type has fixed ones.
 */
function settingsOf(idp: IdpScene): Record<string, unknown> {
	const client = { "client-id": idp.clientId, "client-secret": idp.clientSecret };
	switch (idp.type) {
		case "github":
			return {
				type: "github",
				...client,
				"authorization-endpoint": `${idp.issuer}/login/oauth/authorize`,
				"token-endpoint": `${idp.issuer}/login/oauth/access_token`,
				api: idp.issuer,
				issuer: `${idp.issuer}/login/oauth`,
			};
		case "apple":
			return {
				type: "apple",
				"client-id": idp.clientId,
				...(idp.clientSecret === undefined ? {} : { "client-secret": idp.clientSecret }),
				...(idp.signing?.teamId === undefined ? {} : { "team-id": idp.signing.teamId }),
				...(idp.signing?.keyId === undefined ? {} : { "key-id": idp.signing.keyId }),
				...(idp.signing?.privateKey === undefined ? {} : { "private-key": idp.signing.privateKey }),
				"authorization-endpoint": `${idp.issuer}/auth/authorize`,
				"token-endpoint": `${idp.issuer}/auth/token`,
				"jwks-uri": `${idp.issuer}/auth/keys`,
			};
		case "google":
			return {
				type: "google",
				...client,
				"authorization-endpoint": `${idp.issuer}/o/oauth2/v2/auth`,
				"token-endpoint": `${idp.issuer}/token`,
				"jwks-uri": `${idp.issuer}/oauth2/v3/certs`,
			};
		default:
			return {
				type: "oidc",
				issuer: idp.issuer,
				...client,
				...(idp.readUserinfo ? { "read-userinfo": true } : {}),
				...(idp.endpointHosts ? { "endpoint-hosts": idp.endpointHosts } : {}),
				...(idp.scopes ? { scopes: idp.scopes } : {}),
			};
	}
}

/** The browser half's section: the page that asks the user and, where the scene sets it, the login page. */
const browserSection = (at: GrantsPart) => ({
	page: at.page,
	...(at.loginPage ? { "login-page": at.loginPage } : {}),
});

/** Federation grants' own section: the connections and, where the scene sets it, the lodging limit. */
const grantsSection = (at: GrantsPart) => ({
	connections: Object.fromEntries(
		at.connections.map((c) => [
			c.name,
			{
				idp: c.idp,
				scopes: c.scopes,
				"max-access-token-lifetime": `${c.maxAccessTokenSeconds}s`,
				"scope-subsets": c.scopeSubsets === true,
			},
		]),
	),
	...(at.lodges ? { lodges: at.lodges.limit, "lodge-window": `${at.lodges.windowSeconds}s` } : {}),
	...(at.keepOnSubjectRevocation ? { "keep-on-subject-revocation": true } : {}),
});

const setUp = (part: FederationPart, _: unknown, modules: readonly string[]): NewPart => ({
	modules: [
		"@mod/outbound",
		"@mod/external-jwt",
		"@mod/federation",
		"@mod/idp-oidc",
		...(part.idps.some((idp) => idp.type === "github") ? ["@mod/idp-github"] : []),
		...(part.idps.some((idp) => idp.type === "google") ? ["@mod/idp-google"] : []),
		...(part.idps.some((idp) => idp.type === "apple") ? ["@mod/idp-apple"] : []),
		...(part.keepsUpstreamTokens ? ["@mod/federation-tokens"] : []),
		...(part.grants ? ["@mod/federation-grants", "@mod/federation-grants-connect"] : []),
	],
	...(part.without ? { without: part.without } : {}),
	store: "volatile",
	config: {
		federation: {
			idps: Object.fromEntries(part.idps.map((idp) => [idp.name, settingsOf(idp)])),
			...(part.landing ? { landing: part.landing } : {}),
			...(part.heldPage ? { "held-page": part.heldPage } : {}),
		},
		// Sealing, where what is composed brings it (kept tokens, grants), takes a key of the scene's own.
		...(modules.includes("@mod/seal")
			? { seal: { current: { id: "scene", key: randomBytes(32).toString("base64") } } }
			: {}),
		...(part.grants
			? {
					"federation-grants": grantsSection(part.grants),
					"federation-grants-connect": browserSection(part.grants),
				}
			: {}),
		...(part.linkStepUpPage ? { "federation-link": { "step-up-page": part.linkStepUpPage } } : {}),
		// Every upstream is named so outbound reaches it, and those on plain http at loopback as such.
		outbound: {
			allow: [
				...part.idps.flatMap((idp) => [new URL(idp.issuer).hostname, ...(idp.endpointHosts ?? [])]),
				...(part.ledgerUrls ?? []).map((url) => new URL(url).hostname),
			],
			"plain-loopback": [...part.idps.map((idp) => idp.issuer), ...(part.ledgerUrls ?? [])]
				.map((url) => new URL(url))
				.filter((url) => url.protocol === "http:")
				.map((url) => url.host),
			...(part.proxy ? { proxy: part.proxy } : {}),
		},
	},
});

/** Where a ledger looks users up by upstream identity, it holds the links: users' `link` then answers already or conflict. */
export function onPattern(
	part: FederationPart,
	scene: unknown,
	modules: readonly string[],
): PatternPart {
	if (part.links && modules.includes("@mod/users-http")) {
		return {
			leaveOut:
				"links from the deployment: a ledger looking users up by upstream identity holds the links, so a link answers already or conflict",
		};
	}
	return setUp(part, scene, modules);
}

onNew(federationArea, setUp, onPattern);
