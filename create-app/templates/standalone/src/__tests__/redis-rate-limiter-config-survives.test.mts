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
 * #495 / #496 — end to end, through this template's real resolution chain.
 *
 * `app.mts` resolves `{env}.conf → application.conf → reference.conf` and
 * validates the result with `AppConfigSchema` before `buildModules` runs.
 * The schema strips what it does not declare, so a section declared by a
 * module rather than by core used to vanish at exactly that step — and,
 * because `redisRateLimiterModule.configSchema` carries a
 * `.default({ limit: 60, windowSeconds: 60 })`, the deployment that
 * `docker-compose.production.yml` ships (`RATE_LIMITER_ADAPTER: redis`) then
 * ran on 60 requests / 60 s no matter what the operator wrote.
 *
 * This starts from the shipped configuration, adds the two overrides an
 * operator writes in their own `application.conf` layer, and follows them all
 * the way to the limiter the module builds.
 */

import { fileURLToPath } from "node:url";
import { type AppConfig, AppConfigSchema, type RateLimiter } from "@o3co/auth-provider-core";
import { redisRateLimiterModule } from "@o3co/auth-provider-redis";
import { parseFile, parseString } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { resolveConfigPaths, resolveLibraryReferenceConfPath } from "../configPath.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/**
 * The secrets `application.conf` substitutes, plus the one
 * `docker-compose.production.yml` sets to put the OAuth endpoints behind a
 * shared limiter. Test-only values; #282's entropy floor applies to the two
 * secrets, and the `.` characters keep them out of the base64 alphabet so the
 * UTF-8 length is what counts.
 */
const ENV = {
	OAUTH_JWT_SECRET: "test-secret-rate-limiter-e2e.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "test-session-secret-rate-limiter-e2e.at-least-32-bytes.ok",
	RATE_LIMITER_ADAPTER: "redis",
};

/**
 * What an operator adds to their own `application.conf` layer: per-endpoint
 * budgets for the Redis limiter, and the mTLS posture from
 * `@o3co/auth-provider-mtls`. Neither section appears in anything this
 * template ships, which is why neither was ever covered by a `.conf` diff.
 */
const OPERATOR_OVERRIDES = `
redisRateLimiter {
  limits {
    token { limit = 120, windowSeconds = 60 }
    authorize { limit = 30, windowSeconds = 60 }
  }
}

oauth.mtls {
  enabled = true
  mode = "full-pki"
  trusted-cas = ["-----BEGIN CERTIFICATE-----"]
  full-pki {
    revocation {
      mode = "crl"
      on-unavailable = "reject"
      allowed-hosts = ["crl.example.com"]
    }
  }
}
`;

function resolveShippedConfig(): AppConfig {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	return validate(
		parseString(OPERATOR_OVERRIDES, { env: ENV })
			.withFallback(parseFile(envConfPath, { env: ENV }))
			.withFallback(parseFile(applicationConfPath, { env: ENV }))
			.withFallback(parseFile(resolveLibraryReferenceConfPath(), { env: ENV })),
		AppConfigSchema,
	);
}

/** Counts one request per key, the way an untouched Redis counter would. */
function makeCountingClient(): { incrementWithTtl: (key: string, ttl: number) => Promise<number> } {
	return { incrementWithTtl: async () => 1 };
}

function buildLimiter(config: AppConfig): RateLimiter {
	const provides = (
		redisRateLimiterModule as unknown as {
			provides: Record<string, (deps: Record<string, unknown>) => RateLimiter>;
		}
	).provides;
	const provider = provides.rateLimiter;
	if (!provider) throw new Error("redisRateLimiterModule no longer provides rateLimiter");
	return provider({ config, rateLimiterClient: makeCountingClient() });
}

describe("the shipped configuration reaches the Redis rate limiter (#495)", () => {
	const config = resolveShippedConfig();

	it("selects the Redis adapter the production compose file pins", () => {
		expect(config.rateLimiter?.adapter).toBe("redis");
	});

	it("carries the operator's per-endpoint budgets through the pre-parse", () => {
		expect(config.redisRateLimiter?.limits).toEqual({
			token: { limit: 120, windowSeconds: 60 },
			authorize: { limit: 30, windowSeconds: 60 },
		});
	});

	it("applies the declared budget at /token", async () => {
		const decision = await buildLimiter(config).check("token:ip:203.0.113.5", {
			ip: "203.0.113.5",
		});
		expect(decision.limit).toBe(120);
	});

	it("applies the declared budget at /authorize", async () => {
		const decision = await buildLimiter(config).check("authorize:ip:203.0.113.5", {
			ip: "203.0.113.5",
		});
		expect(decision.limit).toBe(30);
	});

	it("still falls back to the module's default where nothing is declared", async () => {
		// The point of the assertion above: 60 is what EVERY endpoint got while
		// the section was stripped, so a test that only saw 60 could not tell a
		// working configuration from a lost one.
		const decision = await buildLimiter(config).check("introspect:ip:203.0.113.5", {
			ip: "203.0.113.5",
		});
		expect(decision.limit).toBe(60);
	});

	it("keeps seeding /session/login from rateLimit.login", async () => {
		// `resolveSeededLimitSpecs` reads a declared section, so this worked
		// even while `redisRateLimiter` was being stripped — which is why the
		// defect showed up only at the endpoints below it.
		const decision = await buildLimiter(config).check("login:ip:203.0.113.5", {
			ip: "203.0.113.5",
		});
		expect(decision.limit).toBe(config.rateLimit?.login.limit);
	});
});

describe("the shipped configuration carries an mTLS posture through (#496)", () => {
	const config = resolveShippedConfig();

	it("keeps the operator's mTLS block instead of reporting mTLS off", () => {
		expect(config.oauth.mtls).toEqual({
			enabled: true,
			mode: "full-pki",
			"trusted-cas": ["-----BEGIN CERTIFICATE-----"],
			"full-pki": {
				revocation: {
					mode: "crl",
					"on-unavailable": "reject",
					"allowed-hosts": ["crl.example.com"],
				},
			},
		});
	});
});
