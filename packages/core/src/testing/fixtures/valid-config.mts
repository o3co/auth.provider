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

import type { CoreConfig } from "../../config/application.schema.mjs";
import { CORE_RELOCATIONS } from "../../config/core-relocations.mjs";
import { RENAMED_VARIABLES_SECTION } from "../../config/removed-keys.mjs";
import { memoryRateLimiterModule } from "../../ratelimit/module.mjs";
import { renamedVariableCaptures } from "../renamedVariables.mjs";

/**
 * Minimal schema-valid config factories for tests that parse `CoreConfigSchema`
 * or hand `createApp` a configuration without the HOCON load pipeline.
 * Defaults live only in `reference.conf` (ADR 2026-04-30), so each call site
 * would otherwise invent this shape. For production defaults, parse `reference.conf` through the test
 * harness.
 *
 * Deliberate divergences from the `reference.conf` files:
 * - `session-store.storage.type` is `"memory"` (`"redis"` there);
 * - `oauth.jwt.issuer` is a fixed test issuer (`${?OAUTH_JWT_ISSUER}` there);
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
 * Core's own section is type-checked against `CoreConfig` while keeping
 * literal types (`coreConfigForTests`); the other packages' sections are
 * typed as written, since their schemas are their own packages'. Each call
 * returns a fresh, mutable object.
 */

/** What {@link coreConfigForTests} states in core's own section. */
export interface CoreConfigForTestsOptions {
	/** The session requirements the composition expects; none by default. */
	readonly expected?: readonly string[];
	/** The expected requirement held to declaring the second-factor authority; none by default. */
	readonly secondFactorAuthority?: string;
	/** The deployment mode; left unstated by default, which core reads as `unset`. */
	readonly deploymentMode?: "single" | "multi";
	/** The federations, keyed by name (`core.federations`); left unstated by default. */
	readonly federations?: NonNullable<NonNullable<CoreConfig["core"]>["federations"]>;
	/** The slots this composition runs without on purpose (`core.declaredAbsent`); none by default. */
	readonly declaredAbsent?: readonly string[];
	/** `core.sessionLifecycle.sweepIntervalSeconds`, as written; left unstated (a sweep every 60 seconds) by default. */
	readonly sessionLifecycleSweepIntervalSeconds?: unknown;
}

/**
 * Core's own section, `core`, as a configuration fragment to lay over a
 * configuration: the session requirements the composition expects, and the
 * second-factor authority, the deployment mode, the federations and the slots
 * declared absent when given.
 * A fresh object each call.
 */
export function coreConfigForTests(options: CoreConfigForTestsOptions = {}) {
	return {
		core: {
			sessionRequirements: {
				expected: [...(options.expected ?? [])],
				...(options.secondFactorAuthority === undefined
					? {}
					: { secondFactorAuthority: options.secondFactorAuthority }),
			},
			...(options.deploymentMode === undefined
				? {}
				: { deployment: { mode: options.deploymentMode } }),
			...(options.federations === undefined ? {} : { federations: { ...options.federations } }),
			...(options.declaredAbsent === undefined
				? {}
				: { declaredAbsent: [...options.declaredAbsent] }),
			...(options.sessionLifecycleSweepIntervalSeconds === undefined
				? {}
				: {
						sessionLifecycle: {
							sweepIntervalSeconds: options.sessionLifecycleSweepIntervalSeconds,
						},
					}),
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
	};
}

export function makeValidCoreConfig() {
	return {
		...{
			[RENAMED_VARIABLES_SECTION]: renamedVariableCaptures({
				modules: [memoryRateLimiterModule],
				core: CORE_RELOCATIONS,
				env: {},
			}),
		},
		// The oauth module's section, typed as written: its schema is the oauth
		// package's.
		oauth: {
			jwt: {
				issuer: "https://auth.test",
			},
			// The shape `reference.conf` loads to when no lifetime is overridden:
			// the shipped literal sits on the deprecated `expiresIn`, and
			// `resolveAccessTokenLifetime` reads it as a 3600 s default and max.
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
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
		...grantSwitchesForTests(),
	};
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
	};
}

export function makeValidAppConfig() {
	const core = makeValidCoreConfig();
	return {
		...core,
		...makeValidFullSections(),
		// Declares the audit sink and the rate limiter absent (this fixture has
		// no audit trail and no limiter, on purpose); boot refuses either slot
		// unfilled and undeclared once a module reads it. A test of the
		// declared-absence guard removes the entries.
		...coreConfigForTests({ declaredAbsent: ["auditSink", "rateLimiter"] }),
	};
}
