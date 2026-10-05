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
	consoleLogger,
	createRateLimitGuard,
	defineModule,
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
 * `POST /oauth/webauthn/authentication/options` is guarded by the deployment's `rateLimiter` when
 * one is wired: core's `createRateLimitGuard` under the `webauthn-authentication-options` tag,
 * which the module claims with no budget, so the limiter's own `limits` entry for it, else its
 * `defaultLimit`, applies. The outage policy is the limiter's own `failMode`, as for the OAuth
 * endpoints. With no limiter wired (`core.declaredAbsent` lists it), nothing in the module
 * throttles the route. `webauthn.rateLimit` is removed: a configuration setting a key under it,
 * or an environment setting one of its variables, refuses boot.
 */
export const webauthnModule = defineModule<
	| "webauthnCredentialStore"
	| "challengeStore"
	| "challengeCeremony"
	| "keyStore"
	| "oauthTokenSettings"
	| "tokenBindingSettings",
	| "grantPolicy"
	| "rateLimiter"
	| "auditSink"
	| "logger"
	| "refreshTokenFamilyRotation"
	| "subjectRevocation",
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
		// Not a setting either: the options route's limit is the deployment's `rateLimiter`'s.
		relocatedFrom: {
			"webauthn.allowCredentialsForKnownUser": null,
			"webauthn.rateLimit": null,
		},
		// The removed keys' variables, the older rate-limit names included: each set at all refuses
		// boot. The reference captures every name.
		renamedVariables: {
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT: "webauthn.rateLimit.authenticationOptions.limit",
			WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_WINDOW_SECONDS:
				"webauthn.rateLimit.authenticationOptions.windowSeconds",
			WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_LIMIT:
				"webauthn.rateLimit.authenticationOptions.limit",
			WEBAUTHN_RATE_LIMIT_AUTHENTICATION_OPTIONS_WINDOW_SECONDS:
				"webauthn.rateLimit.authenticationOptions.windowSeconds",
			WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER: "webauthn.allowCredentialsForKnownUser",
		},
	},
	requires: [
		"webauthnCredentialStore",
		"challengeStore",
		"challengeCeremony",
		"keyStore",
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
		// The deployment's limiter, which guards the authentication/options route; core attaches
		// its absence policy, so a composition without one lists it in `core.declaredAbsent`.
		"rateLimiter",
		// `rate_limit.unavailable` events during a limiter outage; none when absent.
		"auditSink",
		// Store and limiter outages (`consoleLogger` if unset).
		"logger",
		// The refresh-token family the grant opens, the component the authorization_code grant
		// uses. Optional for compositions that issue no refresh tokens; when wired, a store
		// outage fails closed.
		"refreshTokenFamilyRotation",
		// The subject's revocation boundary, which the grant reads before minting; unread when
		// absent. An unreadable boundary is 503.
		"subjectRevocation",
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
		// The options route's tag, claimed with no budget: the limiter's own
		// `limits.webauthn-authentication-options`, else its `defaultLimit`, applies.
		rateLimitBudgets: {
			[WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG]: () => null,
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
			// writes a challenge per request, so the deployment's limiter, when wired, guards it.
			(deps) => {
				const router = express.Router();
				router.all("/", express.json({ limit: "100kb" }));
				const logger = deps.logger ?? consoleLogger;
				router.post(
					"/",
					// The outage policy is the limiter's own `failMode`, the one the OAuth
					// endpoints apply on the same limiter.
					...(deps.rateLimiter === undefined
						? []
						: [
								createRateLimitGuard({
									limiter: deps.rateLimiter,
									tag: WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT_TAG,
									logger,
									auditSink: deps.auditSink,
								}),
							]),
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
