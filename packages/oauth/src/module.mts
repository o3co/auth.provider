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
	type FederationProviderHandle,
	type Module,
	type ProviderDeps,
	readAccessTokenRevocationMode,
	SUBJECT_REVOCATION_ABSENCE_POLICY,
} from "@o3co/auth-provider-core";
import express from "express";
import { z } from "zod";
import { createOAuthRouter } from "./routes.mjs";

/**
 * Config-slice schema for `oauthModule`. The OAuth `/authorize` route
 * unconditionally reads `config.endpoints.login.url` to build the redirect
 * for unauthenticated requests (`routes.mts:339`). The base
 * `endpoints.login.url` is `z.string().optional()` in `CoreConfigSchema`
 * (production defaults are supplied via HOCON env-var substitution
 * `${?ENDPOINTS_LOGIN_URL}`), but a config that omits the env var passes
 * the base schema, then produces the literal redirect
 * `undefined?redirect_to=...` at request time.
 *
 * Composed via `composeConfigSchema` at validate-manifests step 13:
 * intersection with the base schema yields `endpoints.login.url:
 * z.string().min(1)`, so boot fails with
 * `BootError(reason: "config-validation-failed")` before any request hits
 * the route.
 *
 * Multi-agent review round 2 (Claude + Codex converged): the previous
 * `fullSectionsSchema.pick({ endpoints: true })` only required the
 * `endpoints` and `endpoints.login` *objects* to exist; `url` was still
 * effectively optional. Tightened to `z.string().min(1)` here.
 */
const oauthConfigSchema = z.object({
	endpoints: z.object({
		login: z.object({
			url: z.string().min(1),
		}),
	}),
});

/**
 * Declarative manifest for the OAuth 2.0 endpoint suite.
 *
 * Per A2-γ §3.2.1 + Amendment 1 (§1.1.1 routes-factory shape) +
 * Amendment 3 (§1.1.3 grantHandlerResolver synthetic dep) +
 * Amendment 4 (§1.1.4 four-store session split).
 *
 * Caller surface: `oauthModule({ clientRepository, codeRepository, express? })`
 *   → `oauthModule({ config })`.
 * All dependencies now flow through the typed DI graph (`requires` / `optional`).
 *
 * Route contributions (Amendment 1):
 *   - "oauth-endpoints" @ /oauth — the only route, always contributed.
 *
 * OIDC discovery is NO LONGER an oauth route. oauth instead contributes a
 * `discoveryMetadata` slice (its issuer-relative endpoints + capability
 * metadata); core's `assembleApp` aggregates every module's `discoveryMetadata`
 * (oauth's endpoints, the jwksModule's `jwks_uri`) into the single
 * `/.well-known/openid-configuration` document, mounting it only when an issuer
 * is configured.
 *
 * The v0.4.x lazy closure `() => context.federationProviders` is REMOVED.
 * `deps.federationProviders` is the typed, stable read at factory invocation
 * time (Theme E structural fix).
 *
 * `grantPolicy` and `refreshTokenFamilyRevocation` are declared as
 * ComponentMap slots (colocated augmentations in `core/src/policy/types.mts`
 * and `core/src/refresh-token-family/types.mts`). Both are consumed by
 * `routes.mts` — `grantPolicy.evaluate` gates `/oauth/token`, and
 * `refreshTokenFamilyRevocation.isFamilyRevoked` is read by introspect,
 * userinfo, logout cascade, and federation-token. The legacy
 * `RefreshTokenStoreBase` slot was removed in issue #101 (A3 §5.3).
 *
 * Theme B (one responsibility per module), Theme C (no synthetic-key redeclaration),
 * Theme D (immutability — const defineModule, no ctx mutation),
 * Theme E (structural temporal contracts — stable deps closure replaces lazy getter).
 */
export const oauthModule = (_params: { config: AppConfig }): Module => {
	// Inline route factories so `defineModule` infers the typed `deps`
	// shape from `requires` / `optional` (ProviderDeps<R, O>). Splitting
	// them into a typed const array would require restating R / O at the
	// type level.
	//
	// createOAuthRouter retains its legacy explicit-deps signature
	// (`registry: GrantHandlerResolver`, `getFederationProviders: () => ...`).
	// The route factory bridges typed `deps` to that shape per plan line 710 —
	// the router internals are NOT redesigned in this task.
	//
	// Explicit `defineModule<R, O>` generics: needed so contextual typing
	// reaches the conditional-spread factory below (TS does not propagate
	// the contributes element type through `...(cond ? [fn] : [])`).
	return defineModule<
		"config" | "clientRepository" | "codeRepository" | "keyStore" | "grantHandlerResolver",
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
		| "logger"
	>({
		name: "oauth",
		configSchema: oauthConfigSchema,
		requires: [
			"config", // createOAuthRouter reads config.oauth.jwt.issuer, accessToken / refreshToken expiry
			"clientRepository",
			"codeRepository",
			"keyStore",
			"grantHandlerResolver", // Amendment 3 (§1.1.3) — synthetic, auto-injected by boot planner
		],
		optional: [
			"rateLimiter", // Phase 9 Task 4 augmentation — oauth routes degrade gracefully without
			"auditSink", // Phase 9 Task 4 augmentation — no events emitted when absent
			"grantPolicy", // Phase 9 Task 4 augmentation — gates POST /oauth/token; allow-all when absent
			"refreshTokenFamilyRevocation", // A3 §5.3 — introspect/userinfo/logout cascade family-revocation check
			"accessTokenDenylist", // Wave 1 — RFC 7009 AT revocation; introspect + AT validation consult denylist when wired
			"subjectRevocation", // #296 — per-subject AT watermark; the same surfaces consult it, so a credential change actually invalidates
			"userSessionStore", // Phase 8 A4 four-store split
			"sessionRPRegistry", // Amendment 4 (§1.1.4)
			"sessionFamilyIndex", // Amendment 4 (§1.1.4)
			"sessionFederationIndex", // Amendment 4 (§1.1.4)
			"federationTokenStore", // Phase 9 Task 4 augmentation — federation-token routes
			"federationProviders", // synthetic — boot planner injects ReadonlyMap from federation contributions
			"logger", // D-4 — structured logger; falls back to consoleLogger when absent
		],
		// #363/#375: optional to wire, not optional to decide. `auditSink`
		// absence must be declared with audit.sink.type = "none";
		// `accessTokenDenylist` absence with oauth.revocation.accessToken =
		// "unsupported" (#277's boot refusal, now expressed as a policy).
		absencePolicies: {
			subjectRevocation: SUBJECT_REVOCATION_ABSENCE_POLICY,
			auditSink: AUDIT_SINK_ABSENCE_POLICY,
			accessTokenDenylist: ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY,
		},
		contributes: {
			routes: [
				// oauth-endpoints — always contributed (Theme D: const shape).
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
						logger: deps.logger ?? consoleLogger,
						// Theme E structural fix: typed deps replace the v0.4.x lazy
						// () => ctx.federationProviders closure. The closure here only
						// re-wraps the typed read so the legacy `getFederationProviders`
						// param can be satisfied without changing routes.mts. The cast
						// bridges core's placeholder `FederationProvider = unknown`
						// (from contributes-map.mts) to routes.mts's structural
						// `FederationProviderHandle` — same shape at runtime.
						getFederationProviders: () =>
							deps.federationProviders as ReadonlyMap<string, FederationProviderHandle> | undefined,
					});
					return { id: "oauth-endpoints", mountPath: "/oauth", handler: router };
				},
			],
			// OIDC discovery contribution. core's `assembleApp` merges this with every
			// other module's `discoveryMetadata` (notably the core jwksModule's
			// `jwks_uri`) into the single `/.well-known/openid-configuration` document,
			// prefixing the issuer-relative endpoint paths and owning `issuer` +
			// `id_token_signing_alg_values_supported`. core gates the document on a
			// configured issuer, so oauth contributes unconditionally — the document is
			// simply not emitted when no issuer is set.
			//
			// `jwks_uri` is deliberately NOT contributed here: it is a key-management
			// concern owned by the core jwksModule, so a provider can publish
			// verification keys without the full OAuth grant suite and the advertised
			// URI never drifts from the registered JWKS route. See core/src/jwks/.
			//
			// The same ownership rule places the token-binding metadata elsewhere:
			// `dpop_signing_alg_values_supported` (RFC 9449 §5.1) comes from
			// `@o3co/auth-provider-dpop` and `tls_client_certificate_bound_access_tokens`
			// (RFC 8705 §3.3) from `@o3co/auth-provider-mtls`, each read off the same
			// config the mechanism itself is constructed from (#283).
			discoveryMetadata: [
				(
					deps: ProviderDeps<
						"config" | "clientRepository" | "codeRepository" | "keyStore" | "grantHandlerResolver",
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
					// #283: `POST /oauth/revoke` is mounted unconditionally by
					// `createOAuthRouter`, but "mounted" and "can revoke something" are
					// different claims — the whole point of #277. The gate is therefore
					// "can this endpoint revoke ANYTHING", and it takes both arms of that
					// question at their real resolution rules.
					//
					// The REFRESH arm is pure wiring: `tryRevokeRefreshToken` returns
					// immediately without a `refreshTokenFamilyRevocation`, and the #277
					// mode never touches this path.
					const revokesRefreshTokens = !!deps.refreshTokenFamilyRevocation;
					// The ACCESS arm is wiring AND the declaration. A denylist sitting in
					// the component map is not the capability: `createRevokeRouter`
					// resolves `opts.accessTokenRevocation ?? (denylist ? …)`, so an
					// explicit `"unsupported"` turns the access path off however the
					// composition is wired, and the endpoint answers
					// `unsupported_token_type` instead. Reading the same
					// `readAccessTokenRevocationMode` helper the router reads — rather
					// than re-deriving the rule — is what keeps the two from drifting.
					// An UNDECLARED key reports `undefined`, which both consuming layers
					// (core's boot validator, the router) read as `"denylist"`, so only a
					// literal `"unsupported"` disables this arm.
					const revokesAccessTokens =
						!!deps.accessTokenDenylist &&
						readAccessTokenRevocationMode(deps.config) !== "unsupported";
					// Either arm is enough. RFC 7009 §2.2.1 defines
					// `unsupported_token_type` precisely so an AS may revoke one token
					// type and not the other, so "refresh tokens only" is a revocation
					// endpoint, not a broken one — and the client most in need of finding
					// it (revoking an RT at logout) is served by the arm that still works.
					// Withholding the URL would leave that client unable to revoke
					// anything at all, which is strictly worse than letting it learn the
					// access-token half from the endpoint's own spec-defined error.
					//
					// With NEITHER arm the endpoint still answers RFC 7009's mandatory
					// 200 and nothing happens; advertising that is the #277 failure
					// restated as metadata, so it stays unadvertised.
					//
					// WHICH token types it revokes is still not advertised: RFC 7009 /
					// RFC 8414 define no per-token-type metadata field, and inventing one
					// would put a non-standard claim in a standard document. The
					// access-token answer lives at the endpoint.
					const revocationSupported = revokesRefreshTokens || revokesAccessTokens;
					// #283: RFC 8414 §2 says an OMITTED `grant_types_supported` means
					// `["authorization_code", "implicit"]` — so saying nothing advertised
					// an implicit flow this AS has never implemented, while hiding the
					// grants it does implement (client_credentials, token-exchange,
					// webauthn, …). Read straight off the resolver `/oauth/token`
					// dispatches against, which is also what `allowedGrantTypes` is
					// checked against at dispatch (#312 / #326): a hand-maintained list
					// would drift the moment a grant module is added, removed, or gated
					// off by `oauth.grants.<name>.enabled`.
					//
					// Empty is a legitimate answer (a composition with no grant module
					// registered), and emitting `[]` is still strictly better than
					// omitting the field: it says "no grant types", where omission would
					// assert two.
					const grantTypesSupported = [...deps.grantHandlerResolver.entries()].map(
						([grantType]) => grantType,
					);
					return {
						// oauth owns the authorization-server surface, so it is the
						// provider root: this is the explicit signal that core should
						// synthesize + serve the discovery document (when an issuer is
						// configured). Ancillary contributors (jwksModule's `jwks_uri`)
						// leave it unset.
						providerRoot: true,
						endpoints: {
							authorization_endpoint: "/oauth/authorize",
							token_endpoint: "/oauth/token",
							userinfo_endpoint: "/oauth/userinfo",
							introspection_endpoint: "/oauth/introspect",
							...(revocationSupported ? { revocation_endpoint: "/oauth/revoke" } : {}),
							...(logoutSupported ? { end_session_endpoint: "/oauth/logout" } : {}),
						},
						metadata: {
							response_types_supported: ["code"],
							// #284: OIDC Discovery defaults this to **true** when
							// omitted, so saying nothing claimed support for
							// `request_uri` — which `/authorize` has never
							// implemented. Same shape #283 found in
							// `grant_types_supported`, and worse in consequence: an RP
							// that believed it had sent a signed, tamper-proof request
							// object would have had the query string processed
							// instead. `/authorize` now also refuses the parameter
							// outright with `request_uri_not_supported`.
							//
							// `request_parameter_supported` and
							// `claims_parameter_supported` stay omitted: both default
							// to `false`, so omission already tells the truth, and
							// restating a correct default is noise in a document RPs
							// read.
							request_uri_parameter_supported: false,
							subject_types_supported: ["public"],
							// `groups` is supported by filterClaimsByScope (non-standard but opt-in)
							scopes_supported: ["openid", "profile", "email", "groups"],
							grant_types_supported: grantTypesSupported,
							token_endpoint_auth_methods_supported: [
								"client_secret_basic",
								"client_secret_post",
								"none",
							],
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
							],
							...(revocationSupported
								? {
										revocation_endpoint_auth_methods_supported: [
											"client_secret_basic",
											"client_secret_post",
											"none",
										],
									}
								: {}),
							// #273 + #283: S256 only, and since #273 that is simply true —
							// PKCE is mandatory for every authorization-code client and
							// `ResolvedPkceOptions.supportedMethods` is `["S256"]` with no
							// operator knob that can widen it.
							//
							// `plain` is reachable only through a client registration
							// carrying `allowPlainPkce: true` (`pkceMethodsForClient`), and
							// that is exactly why it stays out of this array.
							// `code_challenge_methods_supported` is SERVER-WIDE metadata
							// (RFC 8414 §2 / RFC 7636 §4.4): every client that reads it
							// concludes "I may use any of these". A per-client exception
							// does not belong in a server-wide array in EITHER direction —
							// listing `plain` tells the clients that cannot use it that they
							// can, and the one client the operator named in its registration
							// does not need discovery to find out.
							//
							// So the advertised set is what EVERY authorization-code client
							// may use and the AS always accepts, which is exactly `S256`.
							code_challenge_methods_supported: ["S256"],
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
