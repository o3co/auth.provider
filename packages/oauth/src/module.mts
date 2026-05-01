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
	defineModule,
	type FederationProviderHandle,
	type GrantRegistry,
	type Module,
	type ProviderDeps,
} from "@o3co/auth-provider-core";
import express from "express";
import * as oidcConfig from "./routes/OpenidConfiguration.mjs";
import { createOAuthRouter } from "./routes.mjs";

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
 *   - "oauth-endpoints" @ /oauth — always contributed.
 *   - "oidc-discovery"  @ /.well-known/openid-configuration — conditional on
 *     config.oauth.jwt.issuer being a non-empty string.
 *
 * The v0.4.x lazy closure `() => context.federationProviders` is REMOVED.
 * `deps.federationProviders` is the typed, stable read at factory invocation
 * time (Theme E structural fix).
 *
 * `grantPolicy` and `refreshTokenStore` are declared as ComponentMap slots
 * (colocated augmentations in `core/src/policy/types.mts` and
 * `core/src/refresh/types.mts`). Both are still consumed by `routes.mts` —
 * `grantPolicy.evaluate` gates `/oauth/token`, and `refreshTokenStore` is
 * read by introspect (family revocation), userinfo, and logout cascade.
 * Phase 6 A3 introduced `refreshTokenRotation`/`refreshTokenFamilyStore`/
 * `refreshTokenFamilyRevocation` as the v0.5.0 successor, but the routes.mts
 * migration to the new triple is deferred to a follow-on task.
 *
 * Theme B (one responsibility per module), Theme C (no synthetic-key redeclaration),
 * Theme D (immutability — const defineModule, no ctx mutation),
 * Theme E (structural temporal contracts — stable deps closure replaces lazy getter).
 */
export const oauthModule = (params: { config: AppConfig }): Module => {
	const issuer = (params.config as { oauth?: { jwt?: { issuer?: unknown } } }).oauth?.jwt?.issuer;
	const hasIssuer = typeof issuer === "string" && issuer.length > 0;

	// Inline route factories so `defineModule` infers the typed `deps`
	// shape from `requires` / `optional` (ProviderDeps<R, O>). Splitting
	// them into a typed const array would require restating R / O at the
	// type level.
	//
	// createOAuthRouter retains its legacy explicit-deps signature
	// (`registry: GrantRegistry`, `getFederationProviders: () => ...`). The
	// route factory bridges typed `deps` to that shape per plan line 710 —
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
		| "refreshTokenStore"
		| "userSessionStore"
		| "sessionRPRegistry"
		| "sessionFamilyIndex"
		| "sessionFederationIndex"
		| "federationTokenStore"
		| "federationProviders"
	>({
		name: "oauth",
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
			"refreshTokenStore", // Phase 9 Task 4 augmentation — introspect/userinfo/logout cascade; A3 successor wiring deferred
			"userSessionStore", // Phase 8 A4 four-store split
			"sessionRPRegistry", // Amendment 4 (§1.1.4)
			"sessionFamilyIndex", // Amendment 4 (§1.1.4)
			"sessionFederationIndex", // Amendment 4 (§1.1.4)
			"federationTokenStore", // Phase 9 Task 4 augmentation — federation-token routes
			"federationProviders", // synthetic — boot planner injects ReadonlyMap from federation contributions
		],
		contributes: {
			routes: [
				// oauth-endpoints — always contributed (Theme D: const shape).
				async (deps) => {
					// GrantHandlerResolver exposes `.get(grantType)`; routes.mts:171
					// only consumes that single method, so structural compat is
					// sufficient. The cast bridges the typed planner shape to the
					// legacy registry param without redesigning createOAuthRouter.
					const registry = deps.grantHandlerResolver as unknown as GrantRegistry;
					const { router } = await createOAuthRouter(express, {
						registry,
						config: deps.config,
						clientRepository: deps.clientRepository,
						codeRepository: deps.codeRepository,
						keyStore: deps.keyStore,
						rateLimiter: deps.rateLimiter,
						auditSink: deps.auditSink,
						grantPolicy: deps.grantPolicy,
						refreshTokenStore: deps.refreshTokenStore,
						userSessionStore: deps.userSessionStore,
						sessionRPRegistry: deps.sessionRPRegistry,
						sessionFamilyIndex: deps.sessionFamilyIndex,
						sessionFederationIndex: deps.sessionFederationIndex,
						federationTokenStore: deps.federationTokenStore,
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
				// oidc-discovery — conditional on config.oauth.jwt.issuer (Theme E:
				// structural conditional evaluated at boot, not at request time).
				// When issuer is absent, the factory short-circuits with a no-op
				// contribution that the planner detects and elides.
				...(hasIssuer
					? [
							(
								deps: ProviderDeps<
									| "config"
									| "clientRepository"
									| "codeRepository"
									| "keyStore"
									| "grantHandlerResolver",
									| "rateLimiter"
									| "auditSink"
									| "grantPolicy"
									| "refreshTokenStore"
									| "userSessionStore"
									| "sessionRPRegistry"
									| "sessionFamilyIndex"
									| "sessionFederationIndex"
									| "federationTokenStore"
									| "federationProviders"
								>,
							) => {
								const logoutSupported =
									!!deps.userSessionStore &&
									!!deps.sessionRPRegistry &&
									!!deps.sessionFamilyIndex &&
									!!deps.sessionFederationIndex &&
									!!deps.federationTokenStore &&
									!!deps.refreshTokenStore;
								return {
									id: "oidc-discovery",
									// The OIDC discovery path `/.well-known/openid-configuration`
									// is fixed by the spec, so `oidcConfig.createRouter` registers
									// the absolute path inside the router itself (kept that way
									// to preserve the public createRouter contract — direct
									// callers do `app.use(createRouter(...))`). Mount at "/" to
									// avoid composing the path twice; otherwise express produces
									// `/.well-known/openid-configuration/.well-known/openid-
									// configuration` and the standard endpoint returns 404.
									mountPath: "/",
									handler: oidcConfig.createRouter(express, {
										issuer: issuer as string,
										signingAlgs: [deps.keyStore.algorithm],
										logoutSupported,
									}),
								};
							},
						]
					: []),
			],
		},
	});
};
