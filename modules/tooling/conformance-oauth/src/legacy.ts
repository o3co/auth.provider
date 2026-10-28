import { onLegacy } from "@mod/conformance-legacy";
import { type ClientScene, type OauthPart, oauthArea } from "./area.ts";

/** The hosts of the clients' key set URLs. */
const keySetHosts = (part: OauthPart) => [
	...new Set(part.clients.flatMap((c) => (c.jwksUri ? [new URL(c.jwksUri).hostname] : []))),
];

/** A client's channel logout fields, as the legacy file names them; a field left out is left out. */
const logoutFields = (logout: NonNullable<ClientScene["logout"]>) =>
	Object.fromEntries(
		Object.entries({
			frontchannelLogoutUri: logout.frontchannelLogoutUri,
			frontchannelLogoutSessionRequired: logout.frontchannelLogoutSessionRequired,
			backchannelLogoutUri: logout.backchannelLogoutUri,
			backchannelLogoutSessionRequired: logout.backchannelLogoutSessionRequired,
		}).filter(([, value]) => value !== undefined),
	);

/** Clients as the legacy file holds them. */
function clientsYaml(part: OauthPart): string {
	const entries = part.clients.map((c) => {
		const fields: Record<string, unknown> = {
			tokenEndpointAuthMethod: c.method,
			allowedGrantTypes: c.grants,
			allowedScopes: c.scopes,
			...(c.secret || c.secretHash ? { clientSecret: c.secretHash ?? c.secret } : {}),
			...(c.keys ? { jwks: { keys: c.keys } } : {}),
			...(c.jwksUri ? { jwksUri: c.jwksUri } : {}),
			...(c.defaultScopes ? { defaultScopes: c.defaultScopes } : {}),
			...(c.audiences ? { allowedAudiences: c.audiences } : {}),
			...(c.redirectUris ? { allowedRedirectUris: c.redirectUris } : {}),
			...(c.firstParty ? { firstParty: true } : {}),
			...(c.upstreamTokens ? { allowedAzpForFederationToken: true } : {}),
			// One list serves both an upstream logout's return and a logout the client starts.
			...(c.upstreamTokens || c.logout?.postLogoutRedirectUris
				? {
						postLogoutRedirectUris: [
							...(c.upstreamTokens?.postLogoutRedirectUris ?? []),
							...(c.logout?.postLogoutRedirectUris ?? []),
						],
					}
				: {}),
			...(c.federationGrants
				? {
						allowedFederationGrantConnections: c.federationGrants.connections,
						federationGrantRedirectUris: c.federationGrants.returnUris,
					}
				: {}),
			...(c.logout ? logoutFields(c.logout) : {}),
		};
		return [c.id, fields];
	});
	return `${JSON.stringify(Object.fromEntries(entries))}\n`;
}

onLegacy(oauthArea, {
	map: (part) => ({
		env: {
			OAUTH_JWT_ISSUER: part.issuer,
			OAUTH_AUTHORIZATION_GRANTS_CLIENT_CREDENTIALS_ENABLED: "true",
			...(part.verifiedEmail ? { OAUTH_REQUIRE_EMAIL_VERIFIED: "true" } : {}),
			...(part.resourceIndicators ? { OAUTH_RESOURCE_INDICATOR_ENABLED: "true" } : {}),
			// A key set on loopback is reached over plain http only from hosts listed as internal.
			...(keySetHosts(part).length > 0
				? { CORE_OUTBOUND_INTERNAL_HOSTS: keySetHosts(part).join(",") }
				: {}),
		},
		files: { "clients.yaml": clientsYaml(part) },
	}),
	cannot: [
		// The legacy build cannot be set up to trust an outside issuer, nor for DPoP.
		"trusted-issuers",
		"dpop",
		// Nor so that revocations and seen assertions fail with its store.
		"store-fault:revocations",
		"store-fault:assertion-replay",
		"store-fault:rate-limit",
	],
	differs: [
		// A public client gets 400 invalid_client for client credentials; Basic and post pass when they agree.
		"public-client-for-client-credentials",
		"two-client-auth-methods",
		// GET on the token endpoint is 404, and a non-form body with valid credentials a server error.
		"get-on-token-endpoint",
		"non-form-token-request",
		// Introspection without a token answers 200.
		"introspection-without-token",
		// RFC 6749 §5.2
		"assertion-with-secret",
		// A client assertion given twice, or only half of one, is answered 400 invalid_request.
		"malformed-assertion",
		// A client assertion for the token endpoint, or naming its audience in a list, is taken.
		"assertion-audience-beside-issuer",
		// For an issuer with a path, the OpenID document is also served at the root.
		"discovery-at-root-for-path-issuer",
		// jwt-bearer refuses an unverified email with the description it gives an unknown subject.
		"email-refusal-description",
		"resource-repeated",
		"resource-client-id",
		// A refused client authentication is recorded, by its reason and the source alone.
		"client-authentication-failure-recorded",
	],
});
