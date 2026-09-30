/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
	ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY,
	type AppConfig,
	AUDIT_SINK_ABSENCE_POLICY,
	consoleLogger,
	defineModule,
	LOGIN_RETURN_PARAMETER,
	loginPageCarriesReturn,
	type Module,
	type ProviderDeps,
	readAccessTokenRevocationMode,
	readAcrTable,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
	stepUpReach,
} from "@o3co/auth-provider-core";
import express from "express";
import { z } from "zod";
import { vouchableAcrValues } from "./acrValues.mjs";
import { CLIENT_ASSERTION_ALGORITHMS } from "./middleware/clientAssertion.mjs";
import { createOAuthRouter } from "./routes.mjs";
import { oauthTokenSettingsFrom } from "./tokenSettings.mjs";

/**
 * Config-slice schema for `oauthModule`. `/authorize` redirects an
 * unauthenticated request to `config.endpoints.login.url` when no module
 * provides the `loginEntry` slot, and the session module builds that slot
 * from the same key, so both rules below hold either way:
 *
 * - non-empty (core's `CoreConfigSchema` requires only a string): an empty
 *   URL names no page;
 * - no `redirect_to` of its own: `/authorize` adds one naming the request to
 *   come back to (core's `LoginEntry` contract), and with two a page reading
 *   the first would send the user to the preconfigured target.
 *
 * Parsed by boot's composed parse over what core's base made of the
 * configuration, so boot fails with
 * `BootError(reason: "config-validation-failed")`, the issue at
 * `endpoints.login.url`, before any request hits the route.
 */
const oauthConfigSchema = z.object({
	endpoints: z.object({
		login: z.object({
			url: z
				.string()
				.min(1)
				.refine((url) => !loginPageCarriesReturn(url), {
					message: `endpoints.login.url must not carry a "${LOGIN_RETURN_PARAMETER}" query parameter of its own: the provider adds "${LOGIN_RETURN_PARAMETER}" when it sends a browser to the login page, naming the request to come back to`,
				}),
		}),
	}),
});

/**
 * Declarative manifest for the OAuth 2.0 endpoint suite. Every dependency
 * flows through the typed DI graph (`requires` / `optional`).
 *
 * Contributes one route, "oauth-endpoints" at `/oauth`, and a
 * `discoveryMetadata` slice (its issuer-relative endpoints and capability
 * metadata); core's `assembleApp` aggregates every module's slice into the
 * single `/.well-known/openid-configuration` document, mounted only when an
 * issuer is configured.
 *
 * `grantPolicy.evaluate` gates `/oauth/token`, and
 * `refreshTokenFamilyRevocation.isFamilyRevoked` is read by introspect,
 * userinfo, the logout cascade and federation-token.
 */
export const oauthModule = (_params: { config: AppConfig }): Module => {
	// Inline route factories, so their `deps` is typed from `defineModule`'s
	// R / O; a typed const array would have to restate them. The factory
	// bridges `deps` to `createOAuthRouter`'s explicit options
	// (`registry: Pick<GrantHandlerResolver, "get">`,
	// `getFederationProviders: () => ...`).
	//
	// The type arguments are written out, though inference from `requires`,
	// `optional` and `provides` would give the same. Written, they infer
	// nothing, so the section schema (none: `never`) and the provided keys
	// `authoritative` is typed against are written too.
	return defineModule<
		| "config"
		| "clientRepository"
		| "keyStore"
		| "grantHandlerResolver"
		| "sessionRequirementResolver",
		| "codeRepository"
		| "rateLimiter"
		| "auditSink"
		| "grantPolicy"
		| "refreshTokenFamilyRevocation"
		| "accessTokenDenylist"
		| "subjectRevocation"
		| "userSessionStore"
		| "sessionRPRegistry"
		| "sessionFamilyIndex"
		| "sessionFederationIndex"
		| "federationTokenStore"
		| "consentStore"
		| "pendingConsentStore"
		| "federationProviders"
		| "replaySeenSet"
		| "loginEntry"
		| "logger",
		never,
		"oauthTokenSettings"
	>({
		name: "oauth",
		configSchema: oauthConfigSchema,
		requires: [
			"config", // createOAuthRouter reads config.oauth.jwt.issuer, accessToken / refreshToken expiry
			"clientRepository",
			"keyStore",
			"grantHandlerResolver", // synthetic, auto-injected by boot planner
			"sessionRequirementResolver", // every consumer of admission takes it (ADR 2026-09-28-session-admission); here it decides the acr drop, and /authorize and the consent step read their sessions through it
		],
		optional: [
			"codeRepository", // where /authorize issues its codes; the router requires it with the authorization_code grant
			"rateLimiter", // oauth routes degrade gracefully without
			"auditSink", // no events emitted when absent
			"grantPolicy", // gates POST /oauth/token; allow-all when absent
			"refreshTokenFamilyRevocation", // introspect/userinfo/logout cascade family-revocation check
			"accessTokenDenylist", // RFC 7009 AT revocation; introspect + AT validation consult denylist when wired
			"subjectRevocation", // per-subject AT watermark; the same surfaces consult it, so a credential change actually invalidates
			"userSessionStore", // this and the next three: the four session stores
			"sessionRPRegistry",
			"sessionFamilyIndex",
			"sessionFederationIndex",
			"federationTokenStore", // federation-token routes
			"consentStore", // the consent step for clients that are not first-party; such clients are refused without it
			"pendingConsentStore", // where the consent step parks a request; the memory consent module provides it with consentStore, and the router refuses one without the other
			"federationProviders", // synthetic — boot planner injects ReadonlyMap from federation contributions
			"replaySeenSet", // jti single-use for private_key_jwt client assertions; server_error on that path when absent
			"loginEntry", // the login page /authorize sends a browser to, which the session module provides; endpoints.login.url is read when absent
			"logger", // structured logger; falls back to consoleLogger when absent
		],
		// Optional to wire, not optional to decide. `auditSink` absence must
		// be declared with audit.sink.type = "none"; `accessTokenDenylist`
		// absence with oauth.revocation.accessToken = "unsupported".
		absencePolicies: {
			subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
			accessTokenDenylist: ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY,
		},
		// What other modules read of `oauth {}` — the issuer, the token
		// lifetimes and the switches — resolved once from the section this
		// module owns, and frozen. The readers outside this package take the
		// slot instead of reading the section. The token-binding dispatch
		// policy is not in it: it is core's, and core reads it itself.
		provides: {
			oauthTokenSettings: (deps) => oauthTokenSettingsFrom(deps.config),
		},
		// One source while this module is loaded. Its own code reads
		// `oauth {}`, so an `overrideComponents` entry for the slot would split
		// what the slot's readers see from what the module does; boot refuses
		// it (`authoritative-component-overridden`). A composition without the
		// module fills the slot itself.
		authoritative: ["oauthTokenSettings"],
		// Eager: core's own machinery — the discovery document's issuer, the
		// CORS table's discovery paths, a requirement's step-up page — reads
		// the slot beside the modules that require it, and core is no
		// module the planner could activate the provider for. Filled whenever
		// this module is installed.
		lifecycle: { oauthTokenSettings: { eager: true } },
		contributes: {
			routes: [
				// oauth-endpoints — always contributed.
				async (deps) => {
					// GrantHandlerResolver is what the synthetic key resolves to
					// and what createOAuthRouter's `registry` param accepts —
					// the type-level read-only projection that exposes
					// `.get(grantType)`, which routes.mts only consumes.
					const registry = deps.grantHandlerResolver;
					const { router } = await createOAuthRouter(express, {
						registry,
						config: deps.config,
						clientRepository: deps.clientRepository,
						codeRepository: deps.codeRepository,
						keyStore: deps.keyStore,
						rateLimiter: deps.rateLimiter,
						auditSink: deps.auditSink,
						grantPolicy: deps.grantPolicy,
						refreshTokenFamilyRevocation: deps.refreshTokenFamilyRevocation,
						accessTokenDenylist: deps.accessTokenDenylist,
						subjectRevocation: deps.subjectRevocation,
						userSessionStore: deps.userSessionStore,
						sessionRPRegistry: deps.sessionRPRegistry,
						sessionFamilyIndex: deps.sessionFamilyIndex,
						sessionFederationIndex: deps.sessionFederationIndex,
						federationTokenStore: deps.federationTokenStore,
						replaySeenSet: deps.replaySeenSet,
						consentStore: deps.consentStore,
						pendingConsentStore: deps.pendingConsentStore,
						...(deps.loginEntry === undefined ? {} : { loginEntry: deps.loginEntry }),
						logger: deps.logger ?? consoleLogger,
						// Wraps the typed read to fit `getFederationProviders`. No
						// cast: the slot and the parameter are the same
						// `FederationProvider`.
						getFederationProviders: () => deps.federationProviders,
						requirements: deps.sessionRequirementResolver,
					});
					return { id: "oauth-endpoints", mountPath: "/oauth", handler: router };
				},
			],
			// OIDC discovery contribution. Core's `assembleApp` merges it with every
			// other module's `discoveryMetadata` into the single
			// `/.well-known/openid-configuration` document, prefixing the
			// issuer-relative endpoint paths and owning `issuer` +
			// `id_token_signing_alg_values_supported`. Core emits the document only
			// when an issuer is configured, so oauth contributes unconditionally.
			//
			// Metadata comes from the module that owns the mechanism. `jwks_uri` is
			// core's jwksModule's, so keys can be published without the OAuth grant
			// suite and the URI never drifts from the JWKS route (core/src/jwks/).
			// `dpop_signing_alg_values_supported` (RFC 9449 §5.1) comes from
			// `@o3co/auth-provider-dpop` and `tls_client_certificate_bound_access_tokens`
			// (RFC 8705 §3.3) from `@o3co/auth-provider-mtls`, each read off the
			// config the mechanism itself is constructed from.
			discoveryMetadata: [
				(
					deps: ProviderDeps<
						| "config"
						| "clientRepository"
						| "keyStore"
						| "grantHandlerResolver"
						| "sessionRequirementResolver",
						| "codeRepository"
						| "rateLimiter"
						| "auditSink"
						| "grantPolicy"
						| "refreshTokenFamilyRevocation"
						| "accessTokenDenylist"
						| "subjectRevocation"
						| "userSessionStore"
						| "sessionRPRegistry"
						| "sessionFamilyIndex"
						| "sessionFederationIndex"
						| "federationTokenStore"
						| "federationProviders"
						| "consentStore"
						| "replaySeenSet"
						| "logger"
					>,
				) => {
					// Logout discovery fields are advertised only when every session store
					// backing the logout cascade is wired. Issuer gating lives in core, so
					// this is purely the store-presence check.
					const logoutSupported =
						!!deps.userSessionStore &&
						!!deps.sessionRPRegistry &&
						!!deps.sessionFamilyIndex &&
						!!deps.sessionFederationIndex &&
						!!deps.federationTokenStore &&
						!!deps.refreshTokenFamilyRevocation;
					// `POST /oauth/revoke` is always mounted, but "mounted" and "can
					// revoke something" are different claims: it is advertised only
					// when it can revoke anything, each arm at its real resolution rule.
					//
					// The refresh arm is pure wiring: `tryRevokeRefreshToken` returns
					// immediately without a `refreshTokenFamilyRevocation`, and the
					// access-token revocation mode never touches this path.
					const revokesRefreshTokens = !!deps.refreshTokenFamilyRevocation;
					// The access arm is wiring AND the declaration: `createRevokeRouter`
					// resolves `opts.accessTokenRevocation ?? (denylist ? …)`, so an
					// explicit `"unsupported"` turns the access path off however the
					// composition is wired, and the endpoint answers
					// `unsupported_token_type`. Reading the router's own
					// `readAccessTokenRevocationMode` keeps the two from drifting. An
					// undeclared key reports `undefined`, which core's boot validator
					// and the router read as `"denylist"`, so only a literal
					// `"unsupported"` disables this arm.
					const revokesAccessTokens =
						!!deps.accessTokenDenylist &&
						readAccessTokenRevocationMode(deps.config) !== "unsupported";
					// Either arm is enough: RFC 7009 §2.2.1 defines
					// `unsupported_token_type` so an AS may revoke one token type and
					// not the other, and withholding the URL would leave a client that
					// revokes an RT at logout unable to revoke anything. With neither
					// arm the endpoint still answers RFC 7009's mandatory 200 and
					// nothing happens, so it stays unadvertised. Which token types it
					// revokes is not advertised: RFC 7009 / RFC 8414 define no
					// per-token-type metadata field.
					const revocationSupported = revokesRefreshTokens || revokesAccessTokens;
					// Client ID Metadata Documents: advertised only when on **and**
					// completable. MCP clients select them on this flag plus `none` in
					// token_endpoint_auth_methods_supported (below, unconditional). A
					// document client is never first-party, so `/authorize` refuses it
					// without a consent store.
					// `private_key_jwt`: advertised only when it can be honoured. The
					// verifier answers `500 server_error` when no `replaySeenSet` is
					// wired rather than accept an unchecked `jti`, so without a store
					// all three endpoints would refuse the method.
					const clientAssertionSupported = deps.replaySeenSet !== undefined;
					// The authorization endpoint, and what a client sends to it — the
					// response type, PKCE, request_uri, acr_values — and a document
					// client, which uses no other grant, exist only with the grant that
					// redeems what `/authorize` issues. Read off the same resolver as
					// `grant_types_supported`, as the router reads it to mount `/authorize`.
					const authorizationEndpoint =
						deps.grantHandlerResolver.get("authorization_code") !== undefined;
					const cimdSupported =
						authorizationEndpoint &&
						(deps.config as { oauth?: { clientIdMetadataDocuments?: { enabled?: unknown } } }).oauth
							?.clientIdMetadataDocuments?.enabled === true &&
						deps.consentStore !== undefined;
					// RFC 8414 §2: an omitted `grant_types_supported` means
					// `["authorization_code", "implicit"]`, which would advertise an
					// implicit flow this AS does not implement. Read straight off the
					// resolver `/oauth/token` dispatches against (also what
					// `allowedGrantTypes` is checked against), so it cannot drift as a
					// grant module is added, removed, or gated off by
					// `oauth.grants.<name>.enabled`. Empty is still emitted: it says "no
					// grant types", where omission would assert two.
					const grantTypesSupported = [...deps.grantHandlerResolver.entries()].map(
						([grantType]) => grantType,
					);
					// The entries `/authorize` answers from: the configured table less
					// what nothing this composition installs can satisfy, computed as
					// the router computes it (which says at boot what it dropped). None
					// without `/authorize`.
					const acrValuesSupported = !authorizationEndpoint
						? []
						: Object.keys(
								vouchableAcrValues(
									readAcrTable(
										(deps.config as { oauth?: { authorize?: { acrValues?: unknown } } }).oauth
											?.authorize?.acrValues,
									),
									deps.federationProviders,
									deps.config,
									stepUpReach(Array.from(deps.sessionRequirementResolver.entries(), ([, r]) => r)),
								).table,
							);
					return {
						// oauth owns the authorization-server surface, so it is the
						// provider root: this is the explicit signal that core should
						// synthesize + serve the discovery document (when an issuer is
						// configured). Ancillary contributors (jwksModule's `jwks_uri`)
						// leave it unset.
						providerRoot: true,
						endpoints: {
							...(authorizationEndpoint ? { authorization_endpoint: "/oauth/authorize" } : {}),
							token_endpoint: "/oauth/token",
							userinfo_endpoint: "/oauth/userinfo",
							introspection_endpoint: "/oauth/introspect",
							...(revocationSupported ? { revocation_endpoint: "/oauth/revoke" } : {}),
							...(logoutSupported ? { end_session_endpoint: "/oauth/logout" } : {}),
						},
						metadata: {
							// RFC 8414 §2 requires the field; with no authorization
							// endpoint it lists none.
							response_types_supported: authorizationEndpoint ? ["code"] : [],
							// OIDC Discovery defaults this to **true** when omitted,
							// which would claim `request_uri` support `/authorize`
							// does not have: an RP that believed it had sent a signed
							// request object would have the query string processed
							// instead. `/authorize` also refuses the parameter with
							// `request_uri_not_supported`. `request_parameter_supported`
							// and `claims_parameter_supported` stay omitted: both
							// default to `false`.
							...(authorizationEndpoint ? { request_uri_parameter_supported: false } : {}),
							...(cimdSupported ? { client_id_metadata_document_supported: true } : {}),
							subject_types_supported: ["public"],
							// `groups` is supported by filterClaimsByScope (non-standard but opt-in)
							scopes_supported: ["openid", "profile", "email", "groups"],
							grant_types_supported: grantTypesSupported,
							// `private_key_jwt` on every client-authenticated endpoint
							// that can honour it, and the assertion algorithms it accepts
							// (RFC 8414 §2). Only asymmetric ones — a shared secret is what
							// the method avoids. The algorithm list travels with the method:
							// advertising algorithms for a method that is not offered says
							// nothing a client can act on.
							token_endpoint_auth_methods_supported: [
								"client_secret_basic",
								"client_secret_post",
								...(clientAssertionSupported ? ["private_key_jwt"] : []),
								"none",
							],
							...(clientAssertionSupported
								? {
										token_endpoint_auth_signing_alg_values_supported: [
											...CLIENT_ASSERTION_ALGORITHMS,
										],
									}
								: {}),
							// RFC 8414 §2: an omitted `*_endpoint_auth_methods_supported`
							// means `["client_secret_basic"]`, which understates both
							// endpoints. They differ from each other on purpose —
							// `/oauth/introspect` builds its client-auth middleware WITHOUT
							// `allowPublicClients` (RFC 7662 §2.1: a client_id is not a
							// secret, so a public client must not be able to query token
							// metadata), while `/oauth/revoke` sets it (RFC 7009 §2.1: a
							// public client may revoke its own tokens).
							introspection_endpoint_auth_methods_supported: [
								"client_secret_basic",
								"client_secret_post",
								...(clientAssertionSupported ? ["private_key_jwt"] : []),
							],
							...(clientAssertionSupported
								? {
										introspection_endpoint_auth_signing_alg_values_supported: [
											...CLIENT_ASSERTION_ALGORITHMS,
										],
									}
								: {}),
							...(revocationSupported
								? {
										revocation_endpoint_auth_methods_supported: [
											"client_secret_basic",
											"client_secret_post",
											...(clientAssertionSupported ? ["private_key_jwt"] : []),
											"none",
										],
										...(clientAssertionSupported
											? {
													revocation_endpoint_auth_signing_alg_values_supported: [
														...CLIENT_ASSERTION_ALGORITHMS,
													],
												}
											: {}),
									}
								: {}),
							// S256 only: PKCE is mandatory for every authorization-code
							// client, and `ResolvedPkceOptions.supportedMethods` is
							// `["S256"]` with no operator knob that can widen it. `plain`,
							// reachable only through a registration carrying
							// `allowPlainPkce: true` (`pkceMethodsForClient`), stays out:
							// this is server-wide metadata (RFC 8414 §2 / RFC 7636 §4.4)
							// that every client reads as "I may use any of these", and the
							// one client the operator named does not need discovery.
							...(authorizationEndpoint ? { code_challenge_methods_supported: ["S256"] } : {}),
							// The acr table's keys, when there is one — less the entries
							// nothing installed can satisfy. Omitted
							// otherwise — an RP that sends `acr_values` to a server with no
							// table gets `unmet_authentication_requirements`, and the metadata
							// says so.
							...(acrValuesSupported.length > 0
								? { acr_values_supported: acrValuesSupported }
								: {}),
							...(logoutSupported
								? {
										backchannel_logout_supported: true,
										backchannel_logout_session_supported: true,
										frontchannel_logout_supported: true,
										frontchannel_logout_session_supported: true,
									}
								: {}),
						},
					};
				},
			],
		},
	});
};
