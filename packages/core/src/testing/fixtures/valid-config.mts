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

/**
 * Minimal schema-valid config factories for tests that need to satisfy
 * `CoreConfigSchema` or `AppConfigSchema` parse without exercising the
 * HOCON load pipeline.
 *
 * These factories return the smallest object shape that passes schema
 * validation; they intentionally diverge from `packages/core/config/
 * reference.conf` for test ergonomics. The deliberate divergences are:
 *
 * - `session.storage.type` is `"memory"` (hocon defaults to `"redis"`).
 * - `federations` is `{}` (hocon ships a built-in `federations.google`
 *   block with `enabled = false`).
 * - `oauth.jwt.signingKey.local.secret` carries an inline test secret
 *   (hocon uses `${?OAUTH_JWT_SECRET}` substitution).
 * - `oauth.jwt.issuer` carries a fixed test issuer (hocon uses
 *   `${?OAUTH_JWT_ISSUER}` substitution). It is required by the schema —
 *   every token this deployment mints is bound to it.
 * - `repositories.{client,user,code}` declare only the discriminator
 *   `type` field; nested adapter-specific fields (`yaml.path`,
 *   `memory.defaultExpiresIn`, …) are omitted because the schema marks
 *   them optional or the adapter-specific factory is not exercised.
 * - `endpoints.client` and `endpoints.authCallback` are omitted because
 *   the schema marks them `.optional()`. Callers exercising those
 *   endpoints' behaviour should add the missing fields per-test.
 * - `oauth.grants` explicitly enables `session`, `authorization_code`, and
 *   `refresh_token` (the three standalone template defaults). These must be
 *   set to `enabled: true` because `oauthAuthorizationModule` uses strict
 *   `=== true` opt-in semantics — `enabled` absent or non-boolean is treated
 *   as not-enabled. Note that `client_credentials` is deliberately omitted —
 *   the factory mirrors the standalone template defaults, where
 *   client_credentials remains off unless the deployment explicitly enables
 *   M2M. The `pkce: { requireS256: false }` sub-object on `authorization_code`
 *   is illustrative of real-config shape; the `grants` schema is
 *   `passthrough` so the value is not enforced.
 *
 * If you need fixture values that match production defaults, parse
 * `reference.conf` directly via the test harness.
 *
 * Background: per ADR 2026-04-30 (schema-strict defaults from hocon),
 * defaults live exclusively in `reference.conf`. Tests that previously
 * relied on schema-side `.default(X)` to populate bare `{}` inputs must
 * now supply explicit values; these factories provide the canonical
 * minimal shape so each call site does not re-invent it.
 *
 * The factories use `satisfies` against `CoreConfig` / `AppConfig` so
 * the returned object is type-checked against the schema *and* preserves
 * the narrow inferred shape (literal enum values such as `algorithm:
 * "HS256"` are not widened to `string`), so consumer tests can assign
 * the result to typed variables without casts.
 *
 * Each factory returns a fresh, mutable object so callers can apply
 * local overrides without bleeding into siblings.
 */

type FullSectionsConfig = z.infer<typeof fullSectionsSchema>;

export function makeValidCoreConfig() {
	return {
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
						secret: "test-secret",
						previousSecrets: [],
					},
				},
			},
			accessToken: { expiresIn: 3600 },
			refreshToken: {
				expiresIn: 86400,
				unknownFamilyPolicy: "reject",
				legacyRtPolicy: "reject",
			},
			grants: {
				session: { enabled: true },
				authorization_code: { enabled: true, pkce: { requireS256: false } },
				refresh_token: { enabled: true },
				// client_credentials: deliberately omitted -- factory mirrors the
				// standalone template defaults, where client_credentials remains
				// off unless the deployment explicitly enables M2M.
			},
			oidcMode: "oidc-required",
		},
	} satisfies CoreConfig;
}

export function makeValidFullSections() {
	return {
		session: {
			secret: "test-session-secret",
			name: "__Host-auth.session",
			maxAge: 3600000,
			secure: true,
			sameSite: "lax",
			domain: null,
			storage: { type: "memory" },
		},
		rateLimit: {
			login: { windowMs: 900000, limit: 20 },
			failMode: "open",
		},
		federations: {},
		repositories: {
			client: { type: "yaml" },
			user: { type: "yaml" },
			code: { type: "memory" },
		},
		endpoints: {
			// `oauthModule.configSchema` requires a non-empty `endpoints.login.url`
			// because `routes.mts:339` builds the unauthenticated /authorize redirect
			// from it. Keeping the fixture valid across all v0.5.0 module schemas.
			login: { url: "/login" },
		},
		cors: { allowedOrigins: [] },
	} satisfies FullSectionsConfig;
}

export function makeValidAppConfig() {
	return {
		...makeValidCoreConfig(),
		...makeValidFullSections(),
	} satisfies AppConfig;
}
