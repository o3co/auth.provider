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
 * The budget in force for every prefix a package owns, through `createApp`,
 * on both bundled limiters: the full set booted on the in-process limiter,
 * and on the Redis one (against the Redis package's shared test container),
 * and the limiter it hands a consumer asked for each prefix's limit and
 * window.
 *
 * One table, prefix by configuration:
 *
 * - shipped: every package on, as the full set boots it;
 * - configured: each owner's own key set by an operator
 *   (`rateLimit.login`, `oauth.deviceAuthorization.rateLimit`,
 *   `webauthn.rateLimit.authenticationOptions`, `mfa.rateLimit.routes`);
 * - declared: the same, and every prefix also declared in the limiter's own
 *   `limits`, which wins;
 * - off: the owners switched off — the device grant disabled, WebAuthn and
 *   the MFA package not installed. The session module is the template's and
 *   always installed, and its schema requires `rateLimit.login`.
 *
 * `token` has no owner: the limiter's `defaultLimit`, or its own `limits`
 * entry.
 */

import type { RateLimiter } from "@o3co/auth-provider-core";
import { SINGLE_ENV } from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type TestRedis, testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import { composeFullSet, type FullSet, type FullSetOptions } from "./full-set.fixture.mts";

type Adapter = "memory" | "redis";
type Cell = "shipped" | "configured" | "declared" | "off";

interface Applied {
	readonly limit: number | undefined;
	readonly windowSeconds: number | undefined;
}

const PREFIXES = [
	"login",
	"device_verification",
	"webauthn-authentication-options",
	"mfa",
	"token",
] as const;
type Prefix = (typeof PREFIXES)[number];

const spec = (limit: number, windowSeconds: number): Applied => ({ limit, windowSeconds });

/** What each prefix is limited by, per configuration: the same on both limiters. */
const TABLE: Readonly<Record<Prefix, Readonly<Record<Cell, Applied>>>> = {
	login: {
		shipped: spec(20, 900),
		configured: spec(7, 60),
		declared: spec(4, 45),
		off: spec(20, 900),
	},
	device_verification: {
		shipped: spec(5, 300),
		configured: spec(3, 120),
		declared: spec(2, 90),
		// Disabled, the grant still carries its default budget; nothing keys the prefix.
		off: spec(5, 300),
	},
	"webauthn-authentication-options": {
		shipped: spec(30, 60),
		configured: spec(11, 30),
		declared: spec(9, 15),
		off: spec(60, 60),
	},
	mfa: {
		// No `mfa.rateLimit.routes` ships: the limiter's default.
		shipped: spec(60, 60),
		configured: spec(13, 240),
		declared: spec(6, 75),
		off: spec(60, 60),
	},
	token: {
		shipped: spec(60, 60),
		configured: spec(60, 60),
		declared: spec(17, 20),
		off: spec(60, 60),
	},
};

/** Each owner's own key, as an operator's layer sets it. */
const OWNERS_KEYS = `
rateLimit.login { windowMs = 60000, limit = 7 }
oauth.deviceAuthorization.rateLimit { limit = 3, windowSeconds = 120 }
webauthn.rateLimit.authenticationOptions { limit = 11, windowSeconds = 30 }
mfa.rateLimit.routes { limit = 13, windowSeconds = 240 }
`;

/** Every prefix in the limiter's own section, beside the owners' keys. */
const declaredLimits = (adapter: Adapter): string => `
${adapter === "redis" ? "redisRateLimiter" : "memoryRateLimiter"}.limits {
  login { limit = 4, windowSeconds = 45 }
  device_verification { limit = 2, windowSeconds = 90 }
  webauthn-authentication-options { limit = 9, windowSeconds = 15 }
  mfa { limit = 6, windowSeconds = 75 }
  token { limit = 17, windowSeconds = 20 }
}
`;

const CELLS: Readonly<Record<Cell, (adapter: Adapter) => FullSetOptions>> = {
	shipped: () => ({}),
	configured: () => ({ operatorHocon: OWNERS_KEYS }),
	declared: (adapter) => ({ operatorHocon: `${OWNERS_KEYS}${declaredLimits(adapter)}` }),
	off: () => ({ features: { deviceGrant: false, webauthn: false, mfa: false } }),
};

let redis: TestRedis;

beforeAll(async () => {
	redis = await testRedis();
});

const envFor = (adapter: Adapter): Record<string, string> =>
	adapter === "memory"
		? { ...SINGLE_ENV }
		: {
				...SINGLE_ENV,
				RATE_LIMITER_ADAPTER: "redis",
				REFRESH_TOKEN_FAMILY_STORE_REDIS_URL: `redis://${redis.host}:${redis.port}/${redis.db}`,
			};

/** A key under `prefix` no earlier check in this run has counted. */
let fresh = 0;
const keyUnder = (prefix: Prefix): string => `${prefix}:ip:198.51.100.${++fresh}`;

/** The limit and the window (whole seconds, from `resetAt`) the limiter applied to a fresh key. */
async function applied(limiter: RateLimiter, prefix: Prefix): Promise<Applied> {
	const before = Date.now();
	const decision = await limiter.check(keyUnder(prefix), { ip: "198.51.100.1" });
	return {
		limit: decision.limit,
		windowSeconds:
			decision.resetAt === undefined
				? undefined
				: Math.round((decision.resetAt.getTime() - before) / 1000),
	};
}

describe.each<Adapter>(["memory", "redis"])("the %s limiter", (adapter) => {
	describe.each<Cell>(["shipped", "configured", "declared", "off"])("%s", (cell) => {
		let composition: FullSet;

		beforeAll(async () => {
			composition = await composeFullSet({ env: envFor(adapter), ...CELLS[cell](adapter) });
			expect(composition.handle.components.rateLimiter?.kind).toBe(adapter);
		});

		afterAll(async () => {
			await composition?.handle.dispose();
		});

		it.each(PREFIXES)("limits %s by the table's budget", async (prefix) => {
			const limiter = composition.handle.components.rateLimiter;
			if (limiter === undefined) throw new Error("the full set booted without a rateLimiter");
			expect(await applied(limiter, prefix)).toEqual(TABLE[prefix][cell]);
		});
	});
});
