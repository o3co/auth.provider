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

import type { z } from "zod";
import type {
	AppConfig,
	CoreConfig,
	fullSectionsSchema,
} from "../../config/application.schema.mjs";
import { CORE_RELOCATIONS } from "../../config/core-relocations.mjs";
import { RENAMED_VARIABLES_SECTION } from "../../config/removed-keys.mjs";
import { memoryRateLimiterModule } from "../../ratelimit/module.mjs";
import { renamedVariableCaptures } from "../renamedVariables.mjs";

/**
 * Minimal schema-valid config factories for tests that parse `CoreConfigSchema`
 * or `AppConfigSchema` without the HOCON load pipeline. Defaults live only in
 * `reference.conf` (ADR 2026-04-30), so each call site would otherwise invent
 * this shape. For production defaults, parse `reference.conf` through the test
 * harness.
 *
 * Deliberate divergences from the `reference.conf` files:
 * - `session-store.storage.type` is `"memory"` (`"redis"` there);
 * - `federations` is `{}` (no built-in `google` block);
 * - the signing key is HS256 (EdDSA there) with an inline secret that clears
 *   the entropy floor, so the fixture carries no PEM material; tests of JWKS
 *   or asymmetric signing build their own key pair;
 * - `oauth.jwt.issuer` is a fixed test issuer (`${?OAUTH_JWT_ISSUER}` there);
 * - `repositories.*` carry only `type`;
 * - the grant switches, in the oauth package's modules' sections, turn on
 *   `oauth-session.enabled` and
 *   `oauth-authorization.grants.{authorizationCode,refreshToken}.enabled`
 *   (off there) and omit `clientCredentials`, as the standalone template does.
 *
 * Like a resolution of `reference.conf` under an environment that sets none
 * of them, it captures every variable core's own section and core's own
 * modules declare renamed, `null` (`renamed-variables`), which boot requires
 * of any configuration.
 *
 * `satisfies CoreConfig` / `AppConfig` type-checks the result while keeping
 * literal types, so tests assign it without casts. Each call returns a fresh,
 * mutable object.
 */

type FullSectionsConfig = z.infer<typeof fullSectionsSchema>;

/** What {@link coreConfigForTests} states in core's own section. */
export interface CoreConfigForTestsOptions {
	/** The session requirements the composition expects; none by default. */
	readonly expected?: readonly string[];
	/** The deployment mode; left unstated by default, which core reads as `unset`. */
	readonly deploymentMode?: "single" | "multi";
}

/**
 * Core's own section, `core`, as a configuration fragment to lay over a
 * configuration: the session requirements the composition expects, and the
 * deployment mode when one is given. A fresh object each call.
 */
export function coreConfigForTests(options: CoreConfigForTestsOptions = {}) {
	return {
		core: {
			sessionRequirements: { expected: [...(options.expected ?? [])] },
			...(options.deploymentMode === undefined
				? {}
				: { deployment: { mode: options.deploymentMode } }),
		},
	} satisfies Pick<CoreConfig, "core">;
}

/**
 * The grant switches the fixture turns on, in the oauth package's modules'
 * sections: the session, authorization-code and refresh-token grants.
 */
function grantSwitchesForTests() {
	return {
		"oauth-session": { enabled: true },
		"oauth-authorization": {
			grants: {
				authorizationCode: { enabled: true },
				refreshToken: { enabled: true },
				// clientCredentials: deliberately omitted -- the fixture mirrors
				// the standalone template, where client_credentials remains off
				// unless the deployment explicitly enables M2M.
			},
		},
	} satisfies Pick<FullSectionsConfig, "oauth-session" | "oauth-authorization">;
}

export function makeValidCoreConfig() {
	const core = {
		...{
			[RENAMED_VARIABLES_SECTION]: renamedVariableCaptures({
				modules: [memoryRateLimiterModule],
				core: CORE_RELOCATIONS,
				env: {},
			}),
		},
		http: { port: 3000, trustProxy: false, readinessTimeoutMs: 1000 },
		logging: { level: "info" },
		oauth: {
			jwt: {
				issuer: "https://auth.test",
				signingKey: {
					provider: "local",
					local: {
						algorithm: "HS256",
						kid: "v0",
						// At least 32 bytes of key material. The '.' characters keep it
						// out of the base64/base64url alphabets, so the UTF-8 reading
						// (38 bytes) is the one that counts (`measureSecretEntropyBytes`).
						secret: "test-hs256-secret.at-least-32-bytes.ok",
						previousSecrets: [],
					},
				},
			},
			// The shape `reference.conf` loads to when no lifetime is overridden:
			// the shipped literal sits on the deprecated `expiresIn`, and
			// `resolveAccessTokenLifetime` reads it as a 3600 s default and max.
			accessToken: { expiresIn: 3600 },
			refreshToken: {
				expiresIn: 86400,
				unknownFamilyPolicy: "reject",
				legacyRtPolicy: "reject",
			},
			oidcMode: "oidc-required",
			// Declares both subject-level revocation slots absent: this fixture
			// has none, on purpose. A test of the declared-absence guard removes
			// the key. `accessToken` is required once `revocation` exists, and
			// `"denylist"` is what an omitted key already reads as.
			revocation: { accessToken: "denylist", subject: "unsupported" },
		},
		// This composition expects nothing of session admission, stated because
		// a createApp test that installs a consumer of admission must state its
		// posture. A test of the declaration itself removes the key.
		...coreConfigForTests(),
	} satisfies CoreConfig;
	return { ...core, ...grantSwitchesForTests() };
}

export function makeValidFullSections() {
	return {
		// The session store's section: the session cookie and its store.
		"session-store": {
			// The secret has a 256-bit entropy floor in the store's schema.
			secret: "test-session-secret.at-least-32-bytes.ok",
			name: "__Host-auth.session",
			maxAge: 3600000,
			secure: true,
			sameSite: "lax",
			domain: null,
			storage: { type: "memory" },
		},
		// The session module's section: the login page the unauthenticated
		// /authorize redirect is built from, and the login's budget.
		session: {
			loginPage: { url: "/login" },
			rateLimit: { login: { windowMs: 900000, limit: 20 } },
		},
		federations: {},
		repositories: {
			client: { type: "yaml" },
			user: { type: "yaml" },
			code: { type: "memory" },
		},
		// Declares the audit sink absent (this fixture has no audit trail, on
		// purpose); the bundled modules refuse an unfilled `auditSink` otherwise.
		// A test of the declared-absence guard removes the key.
		audit: { sink: { type: "none" } },
		cors: { allowedOrigins: [] },
	} satisfies FullSectionsConfig;
}

export function makeValidAppConfig() {
	return {
		...makeValidCoreConfig(),
		...makeValidFullSections(),
	} satisfies AppConfig;
}
