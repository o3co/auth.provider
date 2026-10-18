import { randomBytes } from "node:crypto";
import { onNew } from "@mod/conformance";
import { federationArea, type GrantsPart, type IdpScene } from "./area.ts";

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
			return { type: "oidc", issuer: idp.issuer, ...client };
	}
}

/** Federation grants' own section: the page, the connections and, where the scene sets it, the lodging limit. */
const grantsSection = (at: GrantsPart) => ({
	page: at.page,
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
});

onNew(federationArea, (part) => ({
	modules: [
		"@mod/outbound",
		"@mod/external-jwt",
		"@mod/federation",
		"@mod/idp-oidc",
		...(part.idps.some((idp) => idp.type === "github") ? ["@mod/idp-github"] : []),
		...(part.idps.some((idp) => idp.type === "google") ? ["@mod/idp-google"] : []),
		...(part.idps.some((idp) => idp.type === "apple") ? ["@mod/idp-apple"] : []),
		"@mod/seal",
		...(part.keepsUpstreamTokens ? ["@mod/federation-tokens"] : []),
		...(part.grants ? ["@mod/federation-grants"] : []),
	],
	store: "volatile",
	config: {
		federation: {
			idps: Object.fromEntries(part.idps.map((idp) => [idp.name, settingsOf(idp)])),
			landing: part.landing,
		},
		// Sealing, kept tokens' or a handoff's, takes a key of the scene's own.
		seal: { current: { id: "scene", key: randomBytes(32).toString("base64") } },
		...(part.grants ? { "federation-grants": grantsSection(part.grants) } : {}),
		// Every upstream is named so outbound reaches it, and those on plain http at loopback as such.
		outbound: {
			allow: part.idps.map((idp) => new URL(idp.issuer).hostname),
			"plain-loopback": part.idps
				.map((idp) => new URL(idp.issuer))
				.filter((url) => url.protocol === "http:")
				.map((url) => url.host),
		},
	},
}));
