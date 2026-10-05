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
} from "@o3co/auth-provider-core";
import express from "express";
import { webauthnConfigSchema } from "./config.mjs";
import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE, type WebAuthnGrantDeps } from "./grant.mjs";
import {
	createAuthenticationOptionsHandler,
	WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
} from "./routes/authenticationOptions.mjs";
import { createRegistrationOptionsHandler } from "./routes/registrationOptions.mjs";
import { createRegistrationVerifyHandler } from "./routes/registrationVerify.mjs";

/**
 * Declarative manifest for the WebAuthn passkey module.
 *
 * Its settings are its own section, `webauthn {}`, which boot parses with `webauthnConfigSchema`
 * (strict at every level; defaults from the package's `config/reference.conf`) before any factory
 * runs. The routes and the grant read that section; the module provides it as the
 * `webauthnConfig` slot, for the package's other readers (the WebAuthn second factor), and names
 * the slot `authoritative`. The token lifetimes and the resource-indicator switch come from the
 * `oauthTokenSettings` slot, and the refresh-token binding rule from core's `tokenBindingSettings`
 * slot, both of which it requires; it reads nothing of the whole configuration. Each route has
 * its own id for collision detection and ordering.
 *
 * `POST /oauth/webauthn/authentication/options` is rate-limited by the module itself: core's
 * `createRateLimitGuard` under the `webauthn-authentication-options` tag, on the wired
 * `rateLimiter` or else a per-process memory limiter, which the `deploymentMode` slot decides
 * about (refused under `multi`, a warning when `unset`). The module contributes
 * `webauthn.rateLimit.authenticationOptions` as the tag's budget, which a wired limiter applies;
 * the fallback limiter applies the same key. The outage policy is the limiter's own `failMode`,
 * as for the OAuth endpoints and the MFA routes.
 */
export const webauthnModule = defineModule<
	| "webauthnCredentialStore"
	| "challengeStore"
	| "challengeCeremony"
	| "keyStore"
	| "deploymentMode"
	| "rateLimitBudgetResolver"
	| "oauthTokenSettings"
	| "tokenBindingSettings",
	"grantPolicy" | "rateLimiter" | "auditSink" | "logger" | "refreshTokenFamilyRotation",
	typeof webauthnConfigSchema,
	"webauthnConfig"
>({
	name: "webauthn",
	section: {
		schema: webauthnConfigSchema,
		reference: new URL("../config/reference.conf", import.meta.url),
		// Not a setting: authentication/options never lists a user's credentials, so no ceremony
		// identifies the user and every assertion carries a user handle (WebAuthn §7.2 step 6).
		// The key at any value, and its variable set at all, refuse boot.
		relocatedFrom: { "webauthn.allowCredentialsForKnownUser": null },
		// The two rate-limit variables, named after the paths they set, and the removed key's; the
		// reference captures every name.
		renamedVariables: {
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT: "webauthn.rateLimit.authenticationOptions.limit",
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS:
				"webauthn.rateLimit.authenticationOptions.windowSeconds",
			WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER: "webauthn.allowCredentialsForKnownUser",
		},
	},
	requires: [
		"webauthnCredentialStore",
		"challengeStore",
		"challengeCeremony",
		"keyStore",
		// The replica count core fills: the authentication/options route's per-process fallback
		// is refused under `multi`. Required, so a mode read as absent cannot lift that refusal.
		"deploymentMode",
		// The contributed budgets, which the mismatch warning compares with the section's.
		"rateLimitBudgetResolver",
		// The token lifetimes and the resource-indicator switch, which the grant reads; the oauth
		// module provides it, and a composition without that module fills it itself.
		"oauthTokenSettings",
		// Whether a confidential client's refresh token is bound, which the grant reads; core
		// fills it from `core.tokenBinding` in every composition.
		"tokenBindingSettings",
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
	],
	// The relying party and the rest of the section, for the package's other readers (the
	// WebAuthn second factor): the section as boot parsed it, deeply frozen.
	provides: {
		webauthnConfig: ({ section }) => section,
	},
	// One source while this module is loaded: its routes and grant read the section, so a second
	// source would split what the slot's readers see from what the module does. A deployment
	// module providing the slot is refused as a duplicate provider, a `bootstrapComponents` entry
	// as a collision, and an `overrideComponents` entry as overriding an authoritative slot. A
	// composition without this module fills the slot itself.
	authoritative: ["webauthnConfig"],
	// `auditSink` is optional to wire, not to decide: an unfilled slot needs
	// auditSink listed in core.declaredAbsent or boot refuses (the policy the oauth and session modules share).
	absencePolicies: { auditSink: AUDIT_SINK_ABSENCE_POLICY },
	contributes: {
		// The options route's budget, for every limiter to read; an operator's
		// `limits.webauthn-authentication-options` on the limiter wins.
		rateLimitBudgets: {
			[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: ({ section }) => ({
				...section.rateLimit.authenticationOptions,
			}),
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
				// can be dropped on the way, with the section as the grant's relying party. The
				// `satisfies` checks the other direction: every slot the grant reads is declared
				// here, optional ones included (plain assignability would let an undeclared one
				// through as a permanent `undefined`).
				const { section, ...slots } = deps;
				return createWebAuthnGrant({
					...(slots satisfies Pick<
						typeof slots,
						Exclude<keyof WebAuthnGrantDeps, "webauthnConfig">
					>),
					webauthnConfig: section,
				});
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
						config: deps.section,
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
						config: deps.section,
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
					limit: deps.section.rateLimit.authenticationOptions.limit,
					windowSeconds: deps.section.rateLimit.authenticationOptions.windowSeconds,
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
							message: `core.deployment.mode is "multi" but no shared rateLimiter is wired for POST /oauth/webauthn/authentication/options: the route would fall back to a per-process limiter, so the configured ${spec.limit} / ${spec.windowSeconds}s is really ${spec.limit} × replicas and resets on every deploy. Wire a rateLimiter (adapters.rateLimiter = "redis" in the standalone template), or set core.deployment.mode = "single".`,
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
					// A shared limiter applies the budget registered for the tag: the one this
					// module contributes from its section, since boot refuses an override of
					// it. Boot warns once if the two ever differ. A limiter's own `limits`
					// entry for the tag overrides both and is not visible here.
					const contributed = deps.rateLimitBudgetResolver.get(
						WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
					);
					if (
						contributed?.limit !== spec.limit ||
						contributed.windowSeconds !== spec.windowSeconds
					) {
						logger.warn(
							{
								key: "webauthn.rateLimit.authenticationOptions",
								contributed: contributed === undefined ? null : { ...contributed },
								webauthnConfig: spec,
							},
							"webauthn_authentication_options_budget_mismatch",
						);
					}
				}
				// Fall back rather than leave the route unguarded: this is the credential-store flood
				// and enumeration surface, and a per-process bucket is weak protection, not none.
				// The warning above states which one is in force.
				const limiter: RateLimiter =
					deps.rateLimiter ??
					createMemoryRateLimiter({
						limits: { [WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: spec },
						defaultLimit: spec,
					});

				router.post(
					"/",
					// The outage policy is the limiter's own `failMode`, the one the
					// OAuth endpoints and the MFA routes apply on the same limiter:
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
						config: deps.section,
						challengeStore: deps.challengeStore,
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
