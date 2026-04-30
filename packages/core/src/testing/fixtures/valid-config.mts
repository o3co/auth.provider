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
 * Minimal schema-valid config factories for tests that need to satisfy
 * `CoreConfigSchema` or `AppConfigSchema` parse without exercising the
 * HOCON load pipeline.
 *
 * These factories return the smallest object shape that passes schema
 * validation; they intentionally diverge from `packages/core/config/
 * application.conf` for test ergonomics (e.g. raw secrets instead of
 * env-substituted placeholders, no signing-key alternatives). They are
 * NOT a hocon mirror — if you need fixture values that match production
 * defaults, parse `application.conf` directly via the test harness.
 *
 * Background: per ADR 2026-04-30 (schema-strict defaults from hocon),
 * defaults live exclusively in `application.conf`. Tests that previously
 * relied on schema-side `.default(X)` to populate bare `{}` inputs must
 * now supply explicit values; these factories provide the canonical
 * minimal shape so each call site does not re-invent it.
 *
 * Each factory returns a fresh, mutable object so callers can apply
 * local overrides without bleeding into siblings.
 */

export function makeValidCoreConfig() {
	return {
		http: { port: 3000, trustProxy: false },
		oauth: {
			jwt: {
				signingKey: {
					provider: "local",
					local: {
						algorithm: "HS256",
						kid: "v0",
						secret: "test-secret",
						previousKeys: [],
					},
				},
			},
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: {},
		},
	};
}

export function makeValidFullSections() {
	return {
		session: {
			secret: "test-session-secret",
			maxAge: 3600000,
			secure: true,
			sameSite: "lax" as const,
			domain: null,
			storage: { type: "memory" },
		},
		rateLimit: {
			login: { windowMs: 900000, limit: 20 },
		},
		federations: {},
		repositories: {
			client: { type: "yaml" },
			user: { type: "yaml" },
			code: { type: "memory" },
		},
		endpoints: {
			login: {},
		},
		cors: { allowedOrigins: [] },
	};
}

export function makeValidAppConfig() {
	return {
		...makeValidCoreConfig(),
		...makeValidFullSections(),
	};
}
