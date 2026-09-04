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

import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * #495 / #496 — the five sections `AppConfigSchema` was still dropping.
 *
 * Same mechanism as #472, five more times: the schema is a strip-mode
 * `z.object`, the documented composition root parses through it before
 * `createApp` runs, and every module here supplies its own default — so the
 * override does not fail, it disappears, and the deployment runs on numbers
 * nobody chose.
 *
 * Declared presence-only, like the `redis*` sections beside them: the real
 * bounds and the defaults stay in each module's own `configSchema` and in the
 * `reference.conf` its package ships. The enum-shaped keys keep their
 * vocabulary so a typo fails here by name, and the booleans ride
 * `coerceBooleanFromEnv` (#288) so a `${?VAR}` string still reads.
 *
 * `module-config-key-parity.test.mts` is what keeps the next one from being
 * forgotten the same way.
 */

const base = makeValidAppConfig();

describe("redisRateLimiter survives AppConfigSchema (#495)", () => {
	it("keeps the per-endpoint budgets an operator declares", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			redisRateLimiter: {
				limits: {
					token: { limit: 120, windowSeconds: 60 },
					authorize: { limit: 30, windowSeconds: 60 },
				},
				defaultLimit: { limit: 90, windowSeconds: 30 },
			},
		});
		expect(parsed.redisRateLimiter).toEqual({
			limits: {
				token: { limit: 120, windowSeconds: 60 },
				authorize: { limit: 30, windowSeconds: 60 },
			},
			defaultLimit: { limit: 90, windowSeconds: 30 },
		});
	});

	it("coerces the env-var spelling of a budget, like memoryRateLimiter", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			redisRateLimiter: { limits: { token: { limit: "120", windowSeconds: "60" } } },
		});
		expect(parsed.redisRateLimiter?.limits?.token).toEqual({ limit: 120, windowSeconds: 60 });
	});

	it("refuses a budget that would read as configured and limit nothing", () => {
		expect(() =>
			AppConfigSchema.parse({
				...base,
				redisRateLimiter: { defaultLimit: { limit: 0, windowSeconds: 60 } },
			}),
		).toThrow();
	});

	it("is absent when omitted — the default lives in the module", () => {
		expect(AppConfigSchema.parse(base).redisRateLimiter).toBeUndefined();
	});
});

describe("the remaining redis store namespaces survive AppConfigSchema (#495)", () => {
	it("keeps redisChallengeStore's key namespace", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			redisChallengeStore: { keyPrefix: "tenant-a:chal:" },
		});
		expect(parsed.redisChallengeStore).toEqual({ keyPrefix: "tenant-a:chal:" });
	});

	it("keeps redisReplaySeenSet's key namespace", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			redisReplaySeenSet: { keyPrefix: "tenant-a:replay:" },
		});
		expect(parsed.redisReplaySeenSet).toEqual({ keyPrefix: "tenant-a:replay:" });
	});
});

describe("oauth.mtls survives AppConfigSchema (#496)", () => {
	it("keeps every key the mtls module reads, full-pki included", () => {
		const mtls = {
			enabled: true,
			source: "header",
			"cert-header": "x-client-cert",
			"cert-header-dialect": "plain-pem",
			"trusted-proxies": ["10.0.0.0/8"],
			mode: "full-pki",
			"trusted-cas": ["-----BEGIN CERTIFICATE-----"],
			"full-pki": {
				"max-chain-depth": 4,
				"signature-algorithms": ["ecdsaWithSHA256"],
				"min-rsa-key-bits": 3072,
				revocation: {
					mode: "crl",
					"on-unavailable": "reject",
					"allowed-hosts": ["crl.example.com"],
					"fetch-timeout-ms": 2000,
					"cache-ttl-seconds": 600,
					"max-response-bytes": 65536,
					"ocsp-require-nonce": true,
				},
			},
		};
		expect(AppConfigSchema.parse({ ...base, oauth: { ...base.oauth, mtls } }).oauth.mtls).toEqual(
			mtls,
		);
	});

	it("carries the boot refusals' inputs through, so they stay reachable (#431, #469, #470)", () => {
		// A `full-pki` deployment that names a fetching revocation mode with no
		// `allowed-hosts` is the misconfiguration #470 refuses at boot. The
		// refusal reads the config; before #496 the config never arrived, and
		// `enabled` defaulting to `false` reported mTLS as switched off rather
		// than as wrong.
		const parsed = AppConfigSchema.parse({
			...base,
			oauth: {
				...base.oauth,
				mtls: {
					enabled: true,
					mode: "full-pki",
					"full-pki": { revocation: { mode: "crl", "on-unavailable": "reject" } },
				},
			},
		});
		expect(parsed.oauth.mtls?.enabled).toBe(true);
		expect(parsed.oauth.mtls?.["full-pki"]?.revocation).toEqual({
			mode: "crl",
			"on-unavailable": "reject",
		});
	});

	it("coerces the env-var spelling of enabled (#288)", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			oauth: { ...base.oauth, mtls: { enabled: "true" } },
		});
		expect(parsed.oauth.mtls?.enabled).toBe(true);
	});

	it("refuses a trust posture the module does not have", () => {
		expect(() =>
			AppConfigSchema.parse({ ...base, oauth: { ...base.oauth, mtls: { mode: "pki-ish" } } }),
		).toThrow();
	});

	it("is absent when omitted — the defaults live in the mtls reference.conf", () => {
		expect(AppConfigSchema.parse(base).oauth.mtls).toBeUndefined();
	});
});

describe("oauth.dpop survives AppConfigSchema (#496)", () => {
	it("keeps every key the dpop module reads", () => {
		const dpop = {
			enabled: true,
			"iat-window-seconds": 30,
			"alg-whitelist": ["ES256"],
			"replay-store": "redis",
			"replay-store-ttl-seconds": 600,
		};
		expect(AppConfigSchema.parse({ ...base, oauth: { ...base.oauth, dpop } }).oauth.dpop).toEqual(
			dpop,
		);
	});

	it("coerces the env-var spelling of enabled (#288)", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			oauth: { ...base.oauth, dpop: { enabled: "1" } },
		});
		expect(parsed.oauth.dpop?.enabled).toBe(true);
	});

	it("refuses a replay store the module does not have", () => {
		expect(() =>
			AppConfigSchema.parse({
				...base,
				oauth: { ...base.oauth, dpop: { "replay-store": "postgres" } },
			}),
		).toThrow();
	});

	it("is absent when omitted — the defaults live in the dpop reference.conf", () => {
		expect(AppConfigSchema.parse(base).oauth.dpop).toBeUndefined();
	});
});

describe("webauthn survives AppConfigSchema (#496)", () => {
	it("keeps every key the package's own config schema parses", () => {
		const webauthn = {
			rpId: "example.com",
			rpName: "Example",
			origin: ["https://example.com"],
			challengeTtlMs: 60000,
			attestationPreference: "direct",
			userVerification: "required",
			allowCredentialsForKnownUser: true,
			rateLimit: { authenticationOptions: { limit: 10, windowSeconds: 60 } },
		};
		expect(AppConfigSchema.parse({ ...base, webauthn }).webauthn).toEqual(webauthn);
	});

	it("keeps the single-origin spelling an env substitution produces", () => {
		const parsed = AppConfigSchema.parse({
			...base,
			webauthn: { origin: "https://example.com" },
		});
		expect(parsed.webauthn?.origin).toBe("https://example.com");
	});

	it("refuses a user-verification requirement WebAuthn does not have", () => {
		expect(() =>
			AppConfigSchema.parse({ ...base, webauthn: { userVerification: "optional" } }),
		).toThrow();
	});

	it("is absent when omitted — the defaults live in the webauthn reference.conf", () => {
		expect(AppConfigSchema.parse(base).webauthn).toBeUndefined();
	});
});
