import { onLegacy } from "@mod/conformance-legacy";
import { type CodePart, codeArea } from "./area.ts";

/** Metadata document clients, which the legacy build takes only with its consent store and the code grant. */
const documentsSettings = (documents: NonNullable<CodePart["documents"]>) =>
	`oauth.clientIdMetadataDocuments = ${JSON.stringify({
		enabled: true,
		allowedHosts: documents.allow ?? [],
		deniedHosts: documents.deny ?? [],
		allowedScopes: documents.scopes ?? [],
	})}\n`;

onLegacy(codeArea, {
	map: (part) => ({
		env: {
			// The consent step, for clients that are not first-party, runs only with its stores.
			...(part.withoutConsent ? {} : { ADAPTERS_CONSENT_STORE: "memory" }),
			...(part.refresh ? { OAUTH_AUTHORIZATION_GRANTS_REFRESH_TOKEN_ENABLED: "true" } : {}),
			...(part.sessionGrant ? { OAUTH_SESSION_ENABLED: "true" } : {}),
			...(part.refresh?.lifetimeSeconds
				? { OAUTH_REFRESH_TOKEN_EXPIRES_IN: String(part.refresh.lifetimeSeconds) }
				: {}),
			// A back channel on loopback is reached over plain http only from hosts listed as internal.
			...(part.logout
				? {
						CORE_OUTBOUND_INTERNAL_HOSTS: part.logout.allowed
							.map((origin) => new URL(origin).hostname)
							.join(","),
					}
				: {}),
		},
		settings: [
			// The legacy build holds its acr table in the configuration file, as lists of amr sets.
			part.acr ? `oauth.authorize.acrValues = ${JSON.stringify(part.acr.values)}\n` : "",
			part.documents ? documentsSettings(part.documents) : "",
			part.dpopAtResources ? "dpop { enabled = true }\n" : "",
		].join(""),
		// The standalone build does not load DPoP; the composed entry adds it.
		...(part.dpopAtResources ? { extra: ["dpop"] } : {}),
	}),
	cannot: [
		// The legacy build cannot be set up so codes, or a session grant, fail with its store.
		"store-fault:codes",
		"store-fault:session-grant",
	],
	differs: [
		// A fresh login a client asks for: max_age=0 asks a new one, and a return that dropped its demand is refused.
		"max-age-zero-asks-a-new-login",
		"return-keeps-its-demand",
		// An acr no way of logging in can meet is dropped at boot, and answered as one not known.
		"unmeetable-acr-entry",
		// Ours passes over an acr asked by acr_values and not met, and reads the acr a claims parameter asks for.
		"voluntary-acr",
		"claims-acr",
		// Ours releases the claims a claims request names beyond its scope, held to the values it asks,
		// checks a sub value it asks, and says so in its metadata; the legacy build reads only its acr.
		"claims-names",
		// Ours issues a session grant only to a request with same-origin evidence for its own origin.
		"session-grant-same-origin-only",
		"session-grant-needs-origin-evidence",
		// The session grant issues no scope when none is asked, whatever the client's defaults.
		"session-grant-scope-left-out-without-defaults",
		// A back channel on plain http at loopback is allowed by its host alone, whatever its port.
		"back-channel-by-host-and-port",
		// An expired logout hint is refused; and an old one on a GET gets a page that asks to confirm.
		"expired-logout-hint",
		"old-logout-hint",
		// A resource the exchange refuses still uses the code up.
		"resource-mismatch-keeps-code",
		// Ours answers userinfo only for a token issued with openid.
		"userinfo-needs-openid",
		// Ours takes a front-channel URL only at an origin one of the client's redirect URIs has.
		"frontchannel-within-redirect-origins",
		// Ours refuses a logout whose return the hint's client did not register, leaving the session;
		// the legacy build drops the return and logs out.
		"logout-unregistered-return-refused",
		// Ours refuses a logout whose client_id is not the client the hint was issued to.
		"logout-client-id-checked",
		// Ours refuses a logout request that sends any parameter more than once.
		"logout-repeated-parameter-refused",
		// Ours asks the person to confirm a logout without a hint, on a page of its own, and never returns
		// from it, whatever return the request names; the legacy build refuses one without a hint.
		"logout-confirmed-without-hint",
		// Ours issues a code only for the End-User an id_token_hint names, and refuses one it did not
		// issue; the legacy build reads no hint at authorization.
		"authorize-reads-id-token-hint",
		// Ours refuses prompt=select_account, having no page to choose an account by; the legacy build
		// refuses the word as one it does not know.
		"select-account-refused",
	],
});
