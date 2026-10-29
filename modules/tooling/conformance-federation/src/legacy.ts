import { randomBytes } from "node:crypto";
import { onLegacy } from "@mod/conformance-legacy";
import {
	type FederationPart,
	federationArea,
	type GrantsPart,
	grantsLoginPage,
	type IdpScene,
	linkStepUpPage,
	readsUserinfo,
} from "./area.ts";

/** The lines naming an IdP's type, and the issuer where the type is not one IdP's own. */
const typed = (idp: IdpScene) =>
	idp.type === "github" || idp.type === "google" || idp.type === "apple"
		? `type = "${idp.type}"`
		: `type = "oidc"\n  issuer = ${JSON.stringify(idp.issuer)}`;

/** The lines of the client's secret: the fixed one, and what signs one, as far as each is given. */
const secret = (idp: IdpScene) =>
	Object.entries({
		clientSecret: idp.clientSecret,
		teamId: idp.signing?.teamId,
		keyId: idp.signing?.keyId,
		privateKey: idp.signing?.privateKey,
	})
		.filter(([, value]) => value !== undefined)
		.map(([key, value]) => `  ${key} = ${JSON.stringify(value)}\n`)
		.join("");

/** Where a login lands when it named no target: the scene's landing, else the origin's root. */
const landingOf = (part: FederationPart) => part.landing ?? new URL("/", part.origin).href;

function federations(part: FederationPart): string {
	const entries = part.idps.map(
		(idp) => `core.federations.${idp.name} {
  enabled = true
  ${typed(idp)}
  clientId = ${JSON.stringify(idp.clientId)}
${secret(idp)}  callbackURL = ${JSON.stringify(`${part.origin}/session/oauth/federation/${idp.name}/callback`)}
  redirectAllowlist = ${JSON.stringify(part.returnTargets)}
  authCallbackUrl = ${JSON.stringify(landingOf(part))}
  clientUrl = ${JSON.stringify(landingOf(part))}
}
`,
	);
	return entries.join("");
}

/**
 * Federation grants, installed only when enabled: its connections, a key for the grants it keeps in
 * Redis (beside the subjects' boundaries, as it requires), and no check of an upstream account's
 * holder, which its user file cannot answer.
 */
function grants(part: FederationPart, at: GrantsPart): string {
	const connections = at.connections.map(
		(c) => `  ${c.name} {
    federation = ${JSON.stringify(c.idp)}
    scopes = ${JSON.stringify(c.scopes)}
    boundary = "scene"
    maxAccessTokenLifetime = ${c.maxAccessTokenSeconds}
    callbackURL = ${JSON.stringify(`${part.origin}/session/federation-grants/callback/${c.name}`)}
    allowScopeSubsets = ${c.scopeSubsets === true}
  }
`,
	);
	const key = randomBytes(32).toString("base64");
	// The build counts a client's lodgings on its limiter, under the routes' own prefix.
	const lodges = at.lodges
		? `core-rate-limiter-memory.limits.federation_grants { limit = ${at.lodges.limit}, windowSeconds = ${at.lodges.windowSeconds} }\n`
		: "";
	return `federation-grants {
  connections {
${connections.join("")}  }
}
redis-federation-grant-store { encryptionKeys = [{ id = "scene", key = ${JSON.stringify(key)} }] }
${lodges}`;
}

const grantsEnv = (at: GrantsPart) => ({
	FEDERATION_GRANTS_ENABLED: "true",
	FEDERATION_GRANTS_CONSENT_URL: at.page,
	FEDERATION_GRANTS_IDENTITY_LOOKUP: "unsupported",
	ADAPTERS_FEDERATION_GRANT_STORE: "redis",
	ADAPTERS_FEDERATION_GRANT_INTENT_STORE: "redis",
	ADAPTERS_USER_SESSION_STORES: "redis",
});

onLegacy(federationArea, {
	// The legacy build is given no login page for a connect here, and its step-up page for a link
	// names no start to come back to: these scenes run on this build alone.
	cannot: ["store-fault:federation", grantsLoginPage, linkStepUpPage, readsUserinfo],
	// The legacy Google type sends Google neither a request to log in again nor a max age. A login
	// through Apple, which takes neither, is let in by the legacy build where ours refuses it.
	differs: [
		// A callback lands its browser by 302, a posted answer's too.
		"federation-lands-by-302",
		"google-freshness-not-forwarded",
		"apple-freshness-login-required",
		// Past the cap of pending intents for a client and user, the build refuses with 429.
		"grants-pending-push-out",
		"federation-login-held-at-gates",
		"link-start-origin",
		"link-state-outlives-session",
		"federation-returns-to-authorization",
		"federation-auth-time-from-upstream",
		// The legacy build ties a connection's callback to the session alone: another browser's is
		// refused for its session, and spends the state.
		"grants-round-trip-tied-to-browser",
	],
	map: (part) => {
		// The legacy GitHub, Google and Apple types fix their hosts in code, and the standalone build
		// loads none in a form that takes a fetch: the composed entry adds them and sends their
		// requests to the fake instead.
		const github = part.idps.find((idp) => idp.type === "github");
		const google = part.idps.find((idp) => idp.type === "google");
		const apple = part.idps.find((idp) => idp.type === "apple");
		return {
			settings: federations(part) + (part.grants ? grants(part, part.grants) : ""),
			extra: [
				...(github ? ["github"] : []),
				...(google ? ["google"] : []),
				...(apple ? ["apple"] : []),
			],
			env: {
				...(github ? { LEGACY_GITHUB_BASE: github.issuer } : {}),
				...(google ? { LEGACY_GOOGLE_BASE: google.issuer } : {}),
				...(apple ? { LEGACY_APPLE_BASE: apple.issuer } : {}),
				...(part.grants ? grantsEnv(part.grants) : {}),
			},
		};
	},
});
