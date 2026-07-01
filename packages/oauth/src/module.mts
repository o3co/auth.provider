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
	type AppConfig,
	consoleLogger,
	defineModule,
	type FederationProviderHandle,
	type Module,
	type ProviderDeps,
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
			"userSessionStore", // Phase 8 A4 four-store split
			"sessionRPRegistry", // Amendment 4 (§1.1.4)
			"sessionFamilyIndex", // Amendment 4 (§1.1.4)
			"sessionFederationIndex", // Amendment 4 (§1.1.4)
			"federationTokenStore", // Phase 9 Task 4 augmentation — federation-token routes
			"federationProviders", // synthetic — boot planner injects ReadonlyMap from federation contributions
			"logger", // D-4 — structured logger; falls back to consoleLogger when absent
		],
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
			discoveryMetadata: [
				(
					deps: ProviderDeps<
						"config" | "clientRepository" | "codeRepository" | "keyStore" | "grantHandlerResolver",
						| "rateLimiter"
						| "auditSink"
						| "grantPolicy"
						| "refreshTokenFamilyRevocation"
						| "accessTokenDenylist"
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
							...(logoutSupported ? { end_session_endpoint: "/oauth/logout" } : {}),
						},
						metadata: {
							response_types_supported: ["code"],
							subject_types_supported: ["public"],
							// `groups` is supported by filterClaimsByScope (non-standard but opt-in)
							scopes_supported: ["openid", "profile", "email", "groups"],
							token_endpoint_auth_methods_supported: [
								"client_secret_basic",
								"client_secret_post",
								"none",
							],
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
