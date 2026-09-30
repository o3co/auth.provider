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
 * Minimal schema-valid config factories for tests that parse `CoreConfigSchema`
 * or `AppConfigSchema` without the HOCON load pipeline. Defaults live only in
 * `reference.conf` (ADR 2026-04-30), so each call site would otherwise invent
 * this shape. For production defaults, parse `reference.conf` through the test
 * harness.
 *
 * Deliberate divergences from `reference.conf`:
 * - `session.storage.type` is `"memory"` (`"redis"` there);
 * - `federations` is `{}` (no built-in `google` block);
 * - the signing key is HS256 (EdDSA there) with an inline secret that clears
 *   the entropy floor, so the fixture carries no PEM material; tests of JWKS
 *   or asymmetric signing build their own key pair;
 * - `oauth.jwt.issuer` is a fixed test issuer (`${?OAUTH_JWT_ISSUER}` there);
 * - `repositories.*` carry only `type`;
 * - `oauth.grants` enables `session`, `authorization_code` and
 *   `refresh_token` explicitly (`oauthAuthorizationModule` requires
 *   `enabled === true`) and omits `client_credentials`, as the standalone
 *   template does.
 *
 * `satisfies CoreConfig` / `AppConfig` type-checks the result while keeping
 * literal types, so tests assign it without casts. Each call returns a fresh,
 * mutable object.
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
			grants: {
				session: { enabled: true },
				authorization_code: { enabled: true },
				refresh_token: { enabled: true },
				// client_credentials: deliberately omitted -- factory mirrors the
				// standalone template defaults, where client_credentials remains
				// off unless the deployment explicitly enables M2M.
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
		sessionRequirements: { expected: [] },
	} satisfies CoreConfig;
}

export function makeValidFullSections() {
	return {
		session: {
			// `session.secret` has a 256-bit entropy floor in AppConfigSchema.
			secret: "test-session-secret.at-least-32-bytes.ok",
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
			// Required by `oauthModule.configSchema`: the unauthenticated
			// /authorize redirect is built from it.
			login: { url: "/login" },
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
