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
 * The MFA routes' request-volume budget is the template's own limiter
 * setting: the shipped configuration declares `limits.mfa` as 60 requests per
 * 300 s per client IP in both limiters' sections, so whichever
 * `adapters.rateLimiter` wires applies it to `mfa:ip:<ip>` without a budget
 * contributed by any module. MFA is switched off here, so no module
 * contributes one and the limiter's own entry is all that can apply it; the
 * limiters' default is 60 per 60 s.
 */

import { fileURLToPath } from "node:url";
import {
	createApp,
	defineModule,
	type Module,
	memoryRateLimiterModule,
	type RateLimiter,
} from "@o3co/auth-provider-core";
import { redisRateLimiterModule } from "@o3co/auth-provider-redis";
import { afterEach, describe, expect, it } from "vitest";
import { readOwnLayers, readSwitches, resolveConfigPaths, resolveForBoot } from "../configPath.mjs";
import { loggingModule } from "../modules.mjs";

const configDir = fileURLToPath(new URL("../../config", import.meta.url));

/** The secrets `application.conf` substitutes, test-only values, with MFA off. */
const ENV = {
	KEY_STORE_LOCAL_SECRET: "test-secret-mfa-rate-limit.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_STORE_SECRET: "test-session-secret-mfa-rate-limit.at-least-32-bytes.ok",
	MFA_MODE: "off",
};

/** The shipped budget for the `mfa` prefix. */
const MFA_BUDGET = { limit: 60, windowSeconds: 300 };

const IP = "203.0.113.7";

let disposeBooted: (() => Promise<void>) | undefined;
afterEach(async () => {
	await disposeBooted?.();
	disposeBooted = undefined;
});

/** The shipped production configuration booted with `limiterModule`; the limiter a route module is handed. */
async function bootShippedLimiter(
	adapter: "memory" | "redis",
	limiterModule: Module,
	bootstrapComponents: Record<string, unknown> = {},
): Promise<{ limiter: RateLimiter; config: Record<string, unknown> }> {
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
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, "production");
	const own = readOwnLayers([envConfPath, applicationConfPath], {
		env: { ...ENV, ADAPTERS_RATE_LIMITER: adapter },
	});
	const switches = readSwitches(own);
	expect(switches.adapters.rateLimiter).toBe(adapter);
	const modules = [limiterModule, consumerModule];
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: resolveForBoot(own, [...modules, loggingModule], switches),
			pathResolver: (s: string) => s,
			...bootstrapComponents,
		},
	});
	disposeBooted = () => handle.dispose();
	const config = handle.components.config;
	if (consumed === undefined || config === undefined) {
		throw new Error("the boot filled no config, or handed no consumer the limiter");
	}
	return { limiter: consumed, config: config as unknown as Record<string, unknown> };
}

describe("the shipped configuration's MFA routes budget", () => {
	it("is declared in the in-process limiter's section and applied to mfa:ip:<ip>", async () => {
		const { limiter, config } = await bootShippedLimiter("memory", memoryRateLimiterModule);
		expect(config["core-rate-limiter-memory"]).toMatchObject({ limits: { mfa: MFA_BUDGET } });
		const before = Date.now();
		const decision = await limiter.check(`mfa:ip:${IP}`, { ip: IP });
		expect(decision.limit).toBe(MFA_BUDGET.limit);
		const windowMs = (decision.resetAt?.getTime() ?? 0) - before;
		expect(windowMs).toBeGreaterThan((MFA_BUDGET.windowSeconds - 5) * 1000);
		expect(windowMs).toBeLessThanOrEqual((MFA_BUDGET.windowSeconds + 5) * 1000);
	});

	it("is declared in the Redis limiter's section and applied to mfa:ip:<ip>", async () => {
		const ttls = new Map<string, number>();
		const client = {
			incrementWithTtl: async (key: string, ttl: number) => {
				ttls.set(key, ttl);
				return 1;
			},
		};
		const { limiter, config } = await bootShippedLimiter("redis", redisRateLimiterModule, {
			rateLimiterClient: client,
		});
		expect(config["redis-rate-limiter"]).toMatchObject({ limits: { mfa: MFA_BUDGET } });
		const decision = await limiter.check(`mfa:ip:${IP}`, { ip: IP });
		expect(decision.limit).toBe(MFA_BUDGET.limit);
		expect([...ttls.values()]).toEqual([MFA_BUDGET.windowSeconds]);
	});
});
