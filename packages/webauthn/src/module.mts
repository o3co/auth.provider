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

/**
 * WebAuthn module manifest — ties together the grant handler and the three
 * ceremony endpoints contributed as a deployable unit (Wave 1 §2.4.1 / T31).
 *
 * Contributions:
 *   - `grants[WEBAUTHN_GRANT_TYPE]` — the urn:o3co:oauth:grant-type:webauthn
 *     grant handler (T30). Registered with the boot planner's GrantRegistry
 *     via the `contributes.grants` slot.
 *   - `routes[0]` — POST /oauth/webauthn/registration/options (T27).
 *   - `routes[1]` — POST /oauth/webauthn/registration/verify (T28).
 *   - `routes[2]` — POST /oauth/webauthn/authentication/options (T29).
 *
 * DI requires (all consumed transitively by the grant or routes):
 *   - `webauthnConfig`         — consumer-supplied via a bootstrap module's
 *                                 `provides` slot. Schema exported from this
 *                                 package; NOT auto-intersected into AppConfig.
 *   - `webauthnCredentialStore` — credential storage (findByCredentialId,
 *                                  listByUserId, updateSignCount).
 *   - `challengeStore`         — raw challenge persistence (issue, consume).
 *   - `challengeCeremony`      — 3-outcome replay protection (consume).
 *   - `config`                 — AppConfig; grant reads oauth.accessToken.expiresIn
 *                                and oauth.resourceIndicator.enabled.
 *   - `keyStore`               — JWT signing; consumed by generateToken inside
 *                                the grant handler.
 *
 * `grantPolicy` is declared as OPTIONAL **in the dependency type signature** so
 * the manifest can be wired into compositions where other (non-webauthn) modules
 * may run without policy. But the **grant factory enforces it at boot time**:
 * if `webauthnModule` is wired without a `grantPolicy` slot, the factory throws
 * a clear error (Wave 1 post-merge audit H-2 fail-fast). Unlike `client_credentials`
 * (which falls back to `client.allowedScopes`) and `authorization_code` (narrowed
 * at /authorize), the webauthn grant has NO library-side scope ceiling — the
 * passkey is the authentication event, not a scope authorization. Without
 * `grantPolicy`, an attacker can request any scope and receive it verbatim.
 *
 * When wired, the grant invokes `grantPolicy.evaluate` UNCONDITIONALLY (rt-style),
 * mirroring `refresh_token`. `oauth.resourceIndicator.enabled` gates ONLY whether
 * `body.resource` is forwarded to the policy; it does NOT gate whether the policy
 * runs.
 *
 * Cross-refs: Plan T31 / spec §2.4.1 / PR #172 C1 security fix / Codex Round 3 P1 /
 *             Wave 1 post-merge audit H-2
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	consoleLogger,
	createMemoryRateLimiter,
	createRateLimitGuard,
	defineModule,
	type RateLimiter,
	type RateLimitSpec,
} from "@o3co/auth-provider-core";
import express from "express";
import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "./grant.mjs";
import {
	createAuthenticationOptionsHandler,
	WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
} from "./routes/authenticationOptions.mjs";
import { createRegistrationOptionsHandler } from "./routes/registrationOptions.mjs";
import { createRegistrationVerifyHandler } from "./routes/registrationVerify.mjs";

/**
 * Declarative manifest for the WebAuthn passkey module.
 *
 * Consumer composition roots provide `webauthnConfig` via a small bootstrap
 * module that reads from application config (per A5 §10.2 const-Module
 * pattern). This module does NOT read from AppConfig directly —
 * WebAuthnConfig is a separate component slot (T21 ComponentMap augmentation).
 *
 * The three routes are mounted under dedicated sub-paths so they can
 * each carry individual IDs for collision detection and ordering:
 *   /oauth/webauthn/registration/options   — id: webauthn-registration-options
 *   /oauth/webauthn/registration/verify    — id: webauthn-registration-verify
 *   /oauth/webauthn/authentication/options — id: webauthn-authentication-options
 *
 * `POST /oauth/webauthn/authentication/options` is rate-limited by this module
 * (#281). The route factory mounts core's shared `createRateLimitGuard` under
 * the `webauthn-authentication-options` tag, on the wired `rateLimiter`
 * component when there is one and on a per-process memory limiter (with a
 * warning) when there is not. The spec comes from
 * `webauthnConfig.rateLimit.authenticationOptions`; the outage policy comes
 * from `config.rateLimit.failMode`, the same key the OAuth endpoints and
 * `/session/login` read.
 */
export const webauthnModule = defineModule<
	| "webauthnConfig"
	| "webauthnCredentialStore"
	| "challengeStore"
	| "challengeCeremony"
	| "config"
	| "keyStore",
	"grantPolicy" | "rateLimiter" | "auditSink" | "logger" | "refreshTokenFamilyRotation"
>({
	name: "webauthn",
	requires: [
		"webauthnConfig",
		"webauthnCredentialStore",
		"challengeStore",
		"challengeCeremony",
		"config",
		"keyStore",
	],
	optional: [
		// grantPolicy is REQUIRED by the webauthn grant (H-2 fail-fast in the
		// factory below). Declared `optional` here only so the manifest is
		// composable with non-webauthn modules that don't need policy — the
		// factory throws at boot when this slot is unwired.
		"grantPolicy",
		// #281 — the authentication/options throttle. `rateLimiter` optional so a
		// composition installing no limiter module still boots; unlike the OAuth
		// routes, absence does NOT mean unguarded here (see the route factory).
		"rateLimiter",
		// #281 — `rate_limit.unavailable` during a limiter outage. No events when
		// absent, matching how oauth and session treat the slot.
		"auditSink",
		// #281 — operator-visible outage channel + the fallback-limiter warning.
		"logger",
		// #480 — the refresh-token family the grant opens when the client is
		// allowed `refresh_token`. A3 §5.2, the same component the
		// authorization_code grant registers its initial rt+jwt with. Optional so
		// a composition that issues no refresh tokens still boots; when it IS
		// wired, the grant is fail-closed on a store outage.
		"refreshTokenFamilyRotation",
	],
	// #363: `auditSink` is optional to wire, not optional to decide — an
	// unfilled slot must be declared with audit.sink.type = "none" or boot
	// refuses. Same shared policy as the oauth and session modules.
	absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
	contributes: {
		grants: {
			[WEBAUTHN_GRANT_TYPE]: (deps) => {
				// Wave 1 post-merge audit H-2: fail-fast at boot if grantPolicy is
				// not wired. The webauthn grant has no library-side scope ceiling
				// (no client → no client.allowedScopes); grantPolicy is the sole
				// scope gate. Booting without it silently accepts unbounded scope.
				if (!deps.grantPolicy) {
					throw new Error(
						"webauthn grant requires `grantPolicy` to be wired. " +
							"Unlike client_credentials (client.allowedScopes ceiling) and " +
							"authorization_code (narrowed at /authorize), the webauthn grant " +
							"has no library-side scope ceiling — without grantPolicy the grant " +
							"issues whatever scope the caller requests. Wire a GrantPolicyHook " +
							"via @o3co/auth-provider-policy or your own implementation. If you " +
							"intentionally accept unbounded scope (NOT recommended for " +
							"production), wire a no-op policy returning { outcome: 'allow' }. " +
							"See packages/webauthn/README.md SECURITY — scope authorization.",
					);
				}
				return createWebAuthnGrant({
					config: deps.config,
					keyStore: deps.keyStore,
					webauthnCredentialStore: deps.webauthnCredentialStore,
					challengeCeremony: deps.challengeCeremony,
					grantPolicy: deps.grantPolicy,
					// #480: without this the grant would mint refresh tokens whose
					// family was never registered — no replay detection, and no
					// symptom. The deps bag is built field by field here, so an
					// unnamed slot is a dropped slot (the C1 `grantPolicy` bypass).
					refreshTokenFamilyRotation: deps.refreshTokenFamilyRotation,
					webauthnConfig: {
						rpId: deps.webauthnConfig.rpId,
						origin: deps.webauthnConfig.origin,
						// Forward userVerification so the grant enforces it via SimpleWebAuthn.
						// Cross-refs: Codex Round 2 P1-1
						userVerification: deps.webauthnConfig.userVerification,
					},
				});
			},
		},
		routes: [
			// POST /oauth/webauthn/registration/options
			// express.json() is installed at router level, not at the host app level —
			// createApp installs no global JSON parser (each contributed router installs
			// its own, per the oauthModule routes.mts:215-216 pattern).
			// 100kb limit: realistic WebAuthn blobs are under 10KB; 100kb caps DoS.
			// Cross-refs: Codex Round 4 P1
			(deps) => {
				const router = express.Router();
				router.use(express.json({ limit: "100kb" }));
				router.post(
					"/",
					createRegistrationOptionsHandler({
						config: deps.webauthnConfig,
						challengeStore: deps.challengeStore,
						credentialStore: deps.webauthnCredentialStore,
					}),
				);
				return {
					id: "webauthn-registration-options",
					mountPath: "/oauth/webauthn/registration/options",
					handler: router,
				};
			},
			// POST /oauth/webauthn/registration/verify
			// express.json() at router level — same rationale as registration/options above.
			(deps) => {
				const router = express.Router();
				router.use(express.json({ limit: "100kb" }));
				router.post(
					"/",
					createRegistrationVerifyHandler({
						config: deps.webauthnConfig,
						challengeCeremony: deps.challengeCeremony,
						credentialStore: deps.webauthnCredentialStore,
					}),
				);
				return {
					id: "webauthn-registration-verify",
					mountPath: "/oauth/webauthn/registration/verify",
					handler: router,
				};
			},
			// POST /oauth/webauthn/authentication/options
			// express.json() at router level — same rationale as above.
			//
			// #281: the rate limit is MOUNTED here. It used to be "composed
			// externally at module-wiring time (S10/S15)" — a comment, not a
			// middleware, on the one webauthn route that is unauthenticated and
			// writes a challenge per request.
			(deps) => {
				const router = express.Router();
				router.use(express.json({ limit: "100kb" }));

				const logger = deps.logger ?? consoleLogger;
				const spec: RateLimitSpec = {
					limit: deps.webauthnConfig.rateLimit.authenticationOptions.limit,
					windowSeconds: deps.webauthnConfig.rateLimit.authenticationOptions.windowSeconds,
				};
				if (deps.rateLimiter === undefined) {
					logger.warn(
						{
							limit: spec.limit,
							windowSeconds: spec.windowSeconds,
							tag: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
						},
						"webauthn_authentication_options_rate_limiter_not_shared",
					);
				}
				// Falling back rather than leaving the route unguarded, the same
				// choice `/session/login` makes: this endpoint is the credential-
				// store flood and enumeration surface, so a per-process bucket is
				// weak protection, not absent protection. The warning above says
				// which one is in force so the weakness is stated, not implied.
				// Wire the shared `rateLimiter` component (Redis in a scaled
				// deployment) to get one bucket set across replicas.
				const limiter: RateLimiter =
					deps.rateLimiter ??
					createMemoryRateLimiter({
						limits: { [WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: spec },
						defaultLimit: spec,
					});

				router.post(
					"/",
					// `failMode` is read from the same product-wide config key the
					// OAuth endpoints and `/session/login` read: a limiter outage
					// must not mean "shed load" on one surface and "let everything
					// through" on another.
					createRateLimitGuard({
						limiter,
						tag: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
						failMode: deps.config.rateLimit.failMode,
						logger,
						auditSink: deps.auditSink,
						// This endpoint HAS a documented per-endpoint spec, so the
						// RateLimit-* headers are backed by it when a custom adapter
						// reports no applied limit of its own.
						headerFallback: spec,
					}),
					createAuthenticationOptionsHandler({
						config: deps.webauthnConfig,
						challengeStore: deps.challengeStore,
						credentialStore: deps.webauthnCredentialStore,
					}),
				);
				return {
					id: "webauthn-authentication-options",
					mountPath: "/oauth/webauthn/authentication/options",
					handler: router,
				};
			},
		],
	},
});
