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
 * Sections declared by a module rather than by core (`redisRateLimiter`,
 * `oauth.mtls`) survive this template's real resolution chain, end to end.
 * Starting from the shipped configuration plus an operator's own layer, the
 * overrides are followed through both configuration phases and `createApp`
 * to the limiter the module builds. Were `redisRateLimiter` stripped, the
 * module's `.default({ limit: 60, windowSeconds: 60 })` would put the
 * deployment `docker-compose.production.yml` ships
 * (`RATE_LIMITER_ADAPTER: redis`) on 60 requests / 60 s whatever the
 * operator wrote.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	createApp,
	defineModule,
	type RateLimiter,
} from "@o3co/auth-provider-core";
import { redisRateLimiterModule } from "@o3co/auth-provider-redis";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readOwnLayers, readSwitches, resolveConfigPaths, resolveForBoot } from "../configPath.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/**
 * The secrets `application.conf` substitutes, plus the one
 * `docker-compose.production.yml` sets to put the OAuth endpoints behind a
 * shared limiter. Test-only values; the entropy floor applies to the two
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
 * template ships.
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

/** The composition's own files: the operator's layer over the shipped production ones. */
function ownFiles(): string[] {
	const operator = join(mkdtempSync(join(tmpdir(), "redis-rate-limiter-")), "operator.conf");
	writeFileSync(operator, OPERATOR_OVERRIDES);
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	return [operator, envConfPath, applicationConfPath];
}

/** Counts one request per key, the way an untouched Redis counter would. */
function makeCountingClient(): { incrementWithTtl: (key: string, ttl: number) => Promise<number> } {
	return { incrementWithTtl: async () => 1 };
}

/** The limiter a consumer of the slot is handed, as a route module would be. */
let consumed: RateLimiter | undefined;
const consumerModule = defineModule({
	name: "test:rate-limiter-consumer",
	requires: ["rateLimiter"] as const,
	contributes: {
		grantMiddleware: [
			({ rateLimiter }) => {
				consumed = rateLimiter;
				return null;
			},
		],
	},
});

/** The shipped configuration through both phases, booted with the Redis limiter's module. */
async function bootShipped() {
	const own = readOwnLayers(ownFiles(), { env: ENV });
	const switches = readSwitches(own);
	const modules = [redisRateLimiterModule, consumerModule];
	return {
		switches,
		handle: await createApp({
			modules,
			bootstrapComponents: {
				config: resolveForBoot(own, modules),
				pathResolver: (s: string) => s,
				rateLimiterClient: makeCountingClient() as never,
			},
		}),
	};
}

let booted: Awaited<ReturnType<typeof bootShipped>>;
let config: AppConfig;
let limiter: RateLimiter;

beforeAll(async () => {
	booted = await bootShipped();
	const parsed = booted.handle.components.config;
	const built = consumed;
	if (parsed === undefined || built === undefined) {
		throw new Error("the boot filled no config, or handed no consumer the limiter");
	}
	config = parsed;
	limiter = built;
});

afterAll(async () => {
	await booted?.handle.dispose();
});

describe("the shipped configuration reaches the Redis rate limiter", () => {
	it("selects the Redis adapter the production compose file pins, in phase one", () => {
		expect(booted.switches.rateLimiter?.adapter).toBe("redis");
	});

	it("carries the operator's per-endpoint budgets through boot's parse", () => {
		expect(config.redisRateLimiter?.limits).toEqual({
			token: { limit: 120, windowSeconds: 60 },
			authorize: { limit: 30, windowSeconds: 60 },
		});
	});

	it("applies the declared budget at /token", async () => {
		const decision = await limiter.check("token:ip:203.0.113.5", { ip: "203.0.113.5" });
		expect(decision.limit).toBe(120);
	});

	it("applies the declared budget at /authorize", async () => {
		const decision = await limiter.check("authorize:ip:203.0.113.5", { ip: "203.0.113.5" });
		expect(decision.limit).toBe(30);
	});

	it("still falls back to the module's default where nothing is declared", async () => {
		// 60 is what every endpoint would get were the section stripped, so the
		// budgets above differ from it to tell a working configuration from a
		// lost one.
		const decision = await limiter.check("introspect:ip:203.0.113.5", { ip: "203.0.113.5" });
		expect(decision.limit).toBe(60);
	});

	it("keeps seeding /session/login from rateLimit.login", async () => {
		// `resolveSeededLimitSpecs` reads a section core declares, so this
		// holds even were `redisRateLimiter` stripped.
		const decision = await limiter.check("login:ip:203.0.113.5", { ip: "203.0.113.5" });
		expect(decision.limit).toBe(config.rateLimit?.login.limit);
	});
});

describe("the shipped configuration carries an mTLS posture through", () => {
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
