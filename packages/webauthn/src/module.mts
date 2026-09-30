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
 * WebAuthn module manifest: contributes the `urn:o3co:oauth:grant-type:webauthn` grant and the
 * three ceremony routes under `/oauth/webauthn/` (registration/options, registration/verify,
 * authentication/options).
 *
 * `grantPolicy` is an optional slot only so the manifest composes with other modules; the grant
 * factory refuses to boot without it. This grant has no library-side scope ceiling (the passkey
 * is the authentication event, not a scope authorization), so without a policy it would issue
 * whatever scope the caller requests.
 */

import {
	AUDIT_SINK_ABSENCE_POLICY,
	BootError,
	checkDeploymentMode,
	consoleLogger,
	createMemoryRateLimiter,
	createRateLimitGuard,
	defineModule,
	type RateLimiter,
	type RateLimitSpec,
	requireUsableConfiguredRateLimitSpec,
} from "@o3co/auth-provider-core";
import express from "express";
import { z } from "zod";
import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE, type WebAuthnGrantDeps } from "./grant.mjs";
import {
	createAuthenticationOptionsHandler,
	WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
} from "./routes/authenticationOptions.mjs";
import { createRegistrationOptionsHandler } from "./routes/registrationOptions.mjs";
import { createRegistrationVerifyHandler } from "./routes/registrationVerify.mjs";

/**
 * The `webauthn` section's declaration: the package's `config/reference.conf` (its defaults) and
 * its path. The schema checks nothing: the module reads its settings from the `webauthnConfig`
 * slot, which the deployment fills (with `webauthnConfigSchema`, or hard-coded), and a check
 * here could refuse at boot what that slot accepts.
 */
const WEBAUTHN_SECTION_SCHEMA = z.unknown();

/**
 * `webauthn.rateLimit.authenticationOptions` as the options route's budget, `null` when not given;
 * read as `webauthnConfigSchema` coerces it, and a `RangeError` naming the key when no limiter can
 * apply it.
 */
const authenticationOptionsBudget = (section: unknown): RateLimitSpec | null => {
	const given = (section as { rateLimit?: { authenticationOptions?: unknown } } | null | undefined)
		?.rateLimit?.authenticationOptions;
	if (given === undefined) return null;
	return requireUsableConfiguredRateLimitSpec("webauthn.rateLimit.authenticationOptions", given);
};

/**
 * Declarative manifest for the WebAuthn passkey module.
 *
 * Settings come from the `webauthnConfig` slot, which a bootstrap module fills from application
 * config; this module does not read them from AppConfig. Each route has its own id for collision
 * detection and ordering.
 *
 * `POST /oauth/webauthn/authentication/options` is rate-limited by the module itself: core's
 * `createRateLimitGuard` under the `webauthn-authentication-options` tag, on the wired
 * `rateLimiter` or else a per-process memory limiter, which the `deploymentMode` slot decides
 * about (refused under `multi`, a warning when `unset`). The module contributes
 * `webauthn.rateLimit.authenticationOptions` as the tag's budget, which a wired limiter applies;
 * the fallback limiter applies `webauthnConfig.rateLimit.authenticationOptions`. The outage
 * policy is the limiter's own `failMode`, as for the OAuth endpoints and `/session/login`.
 */
export const webauthnModule = defineModule<
	| "webauthnConfig"
	| "webauthnCredentialStore"
	| "challengeStore"
	| "challengeCeremony"
	| "config"
	| "keyStore"
	| "deploymentMode"
	| "rateLimitBudgetResolver",
	| "grantPolicy"
	| "rateLimiter"
	| "auditSink"
	| "logger"
	| "refreshTokenFamilyRotation"
	| "oauthTokenSettings",
	typeof WEBAUTHN_SECTION_SCHEMA
>({
	name: "webauthn",
	section: {
		schema: WEBAUTHN_SECTION_SCHEMA,
		reference: new URL("../config/reference.conf", import.meta.url),
		at: "webauthn",
	},
	requires: [
		"webauthnConfig",
		"webauthnCredentialStore",
		"challengeStore",
		"challengeCeremony",
		"config",
		"keyStore",
		// The replica count core fills: the authentication/options route's per-process fallback
		// is refused under `multi`. Required, so a mode read as absent cannot lift that refusal.
		"deploymentMode",
		// The budgets in force, which the mismatch warning compares with the slot.
		"rateLimitBudgetResolver",
	],
	optional: [
		// Required by the grant factory, which throws at boot without it; optional here only so
		// the manifest composes with modules that need no policy.
		"grantPolicy",
		// Optional so a composition without a limiter boots; the authentication/options route
		// then falls back to a per-process limiter rather than going unguarded.
		"rateLimiter",
		// `rate_limit.unavailable` events during a limiter outage; none when absent.
		"auditSink",
		// Store and limiter outages, and the fallback-limiter warning (`consoleLogger` if unset).
		"logger",
		// The refresh-token family the grant opens, the component the authorization_code grant
		// uses. Optional for compositions that issue no refresh tokens; when wired, a store
		// outage fails closed.
		"refreshTokenFamilyRotation",
		// What the grant reads of `oauth {}`, provided by the oauth module; the configuration's
		// values when no module provides it.
		"oauthTokenSettings",
	],
	// `auditSink` is optional to wire, not to decide: an unfilled slot needs
	// audit.sink.type = "none" or boot refuses (the policy the oauth and session modules share).
	absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
	contributes: {
		// The options route's budget, for every limiter to read; an operator's
		// `limits.webauthn-authentication-options` on the limiter wins.
		rateLimitBudgets: {
			[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: (deps) =>
				authenticationOptionsBudget(deps.section),
		},
		grants: {
			[WEBAUTHN_GRANT_TYPE]: (deps) => {
				// grantPolicy is this grant's only scope bound; booting without it would accept
				// unbounded scope.
				if (!deps.grantPolicy) {
					// No package ships a GrantPolicyHook, so the message says how to fill the slot.
					throw new Error(
						"webauthn grant requires `grantPolicy` to be wired. " +
							"Unlike client_credentials (client.allowedScopes ceiling) and " +
							"authorization_code (narrowed at /authorize), the webauthn grant " +
							"has no library-side scope ceiling — without grantPolicy the grant " +
							"issues whatever scope the caller requests. Implement a " +
							"GrantPolicyHook (the interface is exported by @o3co/auth-provider-core; " +
							"no package ships one) and fill the `grantPolicy` component slot with it: " +
							"from a module, `defineModule({ name, provides: { grantPolicy: () => hook } })`, " +
							"or `createApp({ bootstrapComponents: { grantPolicy: hook, ... } })`. If you " +
							"intentionally accept unbounded scope (NOT recommended for " +
							"production), provide a policy whose evaluate returns { outcome: 'allow' }. " +
							"See the @o3co/auth-provider-webauthn README, SECURITY — scope authorization.",
					);
				}
				// Handed over whole, as the oauth module does for its grants, so no declared slot
				// can be dropped on the way. The `satisfies` checks the other direction: every slot
				// the grant reads is declared here, optional ones included (plain assignability
				// would let an undeclared one through as a permanent `undefined`).
				return createWebAuthnGrant(deps satisfies Pick<typeof deps, keyof WebAuthnGrantDeps>);
			},
		},
		routes: [
			// POST /oauth/webauthn/registration/options
			// Each contributed router installs its own JSON parser (createApp installs none), on
			// the route's own path (`router.all("/")`), not `router.use`: core mounts routers by
			// prefix, so a `use` parser would also read the bodies of later routes beneath it.
			// 100kb caps DoS; real WebAuthn payloads are under 10KB.
			(deps) => {
				const router = express.Router();
				router.all("/", express.json({ limit: "100kb" }));
				router.post(
					"/",
					createRegistrationOptionsHandler({
						config: deps.webauthnConfig,
						challengeStore: deps.challengeStore,
						credentialStore: deps.webauthnCredentialStore,
						logger: deps.logger ?? consoleLogger,
					}),
				);
				return {
					id: "webauthn-registration-options",
					mountPath: "/oauth/webauthn/registration/options",
					handler: router,
				};
			},
			// POST /oauth/webauthn/registration/verify
			// express.json() on the route's own path — same rationale as registration/options above.
			(deps) => {
				const router = express.Router();
				router.all("/", express.json({ limit: "100kb" }));
				router.post(
					"/",
					createRegistrationVerifyHandler({
						config: deps.webauthnConfig,
						challengeCeremony: deps.challengeCeremony,
						credentialStore: deps.webauthnCredentialStore,
						logger: deps.logger ?? consoleLogger,
					}),
				);
				return {
					id: "webauthn-registration-verify",
					mountPath: "/oauth/webauthn/registration/verify",
					handler: router,
				};
			},
			// POST /oauth/webauthn/authentication/options
			// express.json() on the route's own path, as above. The route is unauthenticated and
			// writes a challenge per request, so the module mounts its rate limit here.
			(deps) => {
				const router = express.Router();
				router.all("/", express.json({ limit: "100kb" }));

				const logger = deps.logger ?? consoleLogger;
				const deploymentMode = checkDeploymentMode(deps.deploymentMode, "webauthn: deploymentMode");
				const spec: RateLimitSpec = {
					limit: deps.webauthnConfig.rateLimit.authenticationOptions.limit,
					windowSeconds: deps.webauthnConfig.rateLimit.authenticationOptions.windowSeconds,
				};
				if (deps.rateLimiter === undefined) {
					// The per-process fallback below is replica-unsafe state, built here where the
					// boot guard does not see it, so it asks the `deploymentMode` slot itself:
					// "multi" refuses (the budget would multiply by the replica count), "single"
					// is silent, "unset" warns. The planner wraps the throw as
					// `contribute-factory-failed`, with this error as its `cause`.
					if (deploymentMode === "multi") {
						throw new BootError({
							stage: "applyContributions",
							reason: "replica-unsafe-adapter",
							message: `deployment.mode is "multi" but no shared rateLimiter is wired for POST /oauth/webauthn/authentication/options: the route would fall back to a per-process limiter, so the configured ${spec.limit} / ${spec.windowSeconds}s is really ${spec.limit} × replicas and resets on every deploy. Wire a rateLimiter (rateLimiter.adapter = "redis"), or set deployment.mode = "single".`,
							details: { reason: "replica-unsafe-adapter", modules: ["webauthn"] },
						});
					}
					if (deploymentMode !== "single") {
						logger.warn(
							{
								limit: spec.limit,
								windowSeconds: spec.windowSeconds,
								tag: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
							},
							"webauthn_authentication_options_rate_limiter_not_shared",
						);
					}
				} else {
					// A shared limiter applies the budget in force for the tag, not this slot;
					// boot warns once when they differ. A limiter's own `limits` entry for the
					// tag overrides both and is not visible here.
					const inForce = deps.rateLimitBudgetResolver.get(
						WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
					);
					if (inForce?.limit !== spec.limit || inForce.windowSeconds !== spec.windowSeconds) {
						logger.warn(
							{
								key: "webauthn.rateLimit.authenticationOptions",
								inForce: inForce === undefined ? null : { ...inForce },
								webauthnConfig: spec,
							},
							"webauthn_authentication_options_budget_mismatch",
						);
					}
				}
				// Fall back rather than leave the route unguarded, as `/session/login` does: this is
				// the credential-store flood and enumeration surface, and a per-process bucket is
				// weak protection, not none. The warning above states which one is in force.
				const limiter: RateLimiter =
					deps.rateLimiter ??
					createMemoryRateLimiter({
						limits: { [WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: spec },
						defaultLimit: spec,
					});

				router.post(
					"/",
					// The outage policy is the limiter's own `failMode`, the one the
					// OAuth endpoints and `/session/login` apply on the same limiter:
					// an outage must not mean "shed load" on one surface and "let
					// everything through" on another.
					createRateLimitGuard({
						limiter,
						tag: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
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
						logger,
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
