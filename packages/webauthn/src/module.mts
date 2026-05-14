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
 * `grantPolicy` is declared as OPTIONAL in this module (same as oauthModule /
 * oauthAuthorizationModule). When wired by the consumer, the boot planner
 * injects it into `deps`; when absent, `deps.grantPolicy` is `undefined`.
 * The grant invokes `grantPolicy.evaluate` UNCONDITIONALLY whenever it is
 * wired (rt-style), mirroring `refresh_token`. `oauth.resourceIndicator.enabled`
 * gates ONLY whether `body.resource` is forwarded to the policy; it does NOT
 * gate whether the policy runs. Without `grantPolicy` wired, the grant issues
 * whatever scope the caller requests — operators MUST wire `grantPolicy` to
 * bound scope (CP-18 fail-closed once wired).
 *
 * Cross-refs: Plan T31 / spec §2.4.1 / PR #172 C1 security fix / Codex Round 3 P1
 */

import { defineModule } from "@o3co/auth-provider-core";
import express from "express";
import { createWebAuthnGrant, WEBAUTHN_GRANT_TYPE } from "./grant.mjs";
import { createAuthenticationOptionsHandler } from "./routes/authenticationOptions.mjs";
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
 * Rate-limit for authentication/options is composed externally — the handler
 * factory (T29) has no rateLimiter dep. Per project convention (S10/S15),
 * rate-limit middleware is wired at the route level via middleware composition,
 * not as a handler-factory dependency. To apply, wrap the handler inside an
 * Express router with the RateLimiter middleware before mounting.
 */
export const webauthnModule = defineModule<
	| "webauthnConfig"
	| "webauthnCredentialStore"
	| "challengeStore"
	| "challengeCeremony"
	| "config"
	| "keyStore",
	"grantPolicy"
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
		"grantPolicy", // CP-18: gates the webauthn grant when resourceIndicator.enabled; absent = allow-all
	],
	contributes: {
		grants: {
			[WEBAUTHN_GRANT_TYPE]: (deps) =>
				createWebAuthnGrant({
					config: deps.config,
					keyStore: deps.keyStore,
					webauthnCredentialStore: deps.webauthnCredentialStore,
					challengeCeremony: deps.challengeCeremony,
					grantPolicy: deps.grantPolicy,
					webauthnConfig: {
						rpId: deps.webauthnConfig.rpId,
						origin: deps.webauthnConfig.origin,
						// Forward userVerification so the grant enforces it via SimpleWebAuthn.
						// Cross-refs: Codex Round 2 P1-1
						userVerification: deps.webauthnConfig.userVerification,
					},
				}),
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
			// Rate-limit is composed externally — no rateLimiter arg on handler (T29 / S10/S15).
			// express.json() at router level — same rationale as above.
			(deps) => {
				const router = express.Router();
				router.use(express.json({ limit: "100kb" }));
				router.post(
					"/",
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
