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
 *   (`session.rateLimit.login`, `device-grant.rateLimit`,
 *   `webauthn.rateLimit.authenticationOptions`);
 * - declared: the same, and every prefix but a verifier's also declared in
 *   the limiter's own `limits`, which wins; `login` and `device_verification`
 *   stay their owners', since a limiter's `limits` may not name them;
 * - off: the owners switched off — the device grant disabled, WebAuthn and
 *   the MFA package not installed;
 * - off, keys set: the same, with each owner's key set. A key whose owner is
 *   not installed, or installed and switched off (the device grant), sets no
 *   budget.
 *
 * `token` has no owner, and `mfa`'s owner claims it with no budget: the
 * limiter's `defaultLimit`, or its own `limits` entry. `login` and
 * `device_verification` are claimed with no budget: their
 * owners count attempts on the attempt counter, against
 * `session.rateLimit.login` and `device-grant.rateLimit`, so the limiter
 * holds only its `defaultLimit` for each prefix, whatever the owner's key
 * says.
 */

import {
	BootError,
	defineModule,
	type RateLimiter,
	verifierLimitClaim,
} from "@o3co/auth-provider-core";
import {
	compose,
	login,
	SINGLE_ENV,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type TestRedis, testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import {
	composeFullSet,
	type FullSet,
	type FullSetOptions,
	fullSetOptions,
} from "./full-set.fixture.mts";

type Adapter = "memory" | "redis";
type Cell = "shipped" | "configured" | "declared" | "off" | "offConfigured";

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
		shipped: spec(60, 60),
		configured: spec(60, 60),
		declared: spec(60, 60),
		off: spec(60, 60),
		offConfigured: spec(60, 60),
	},
	device_verification: {
		shipped: spec(60, 60),
		configured: spec(60, 60),
		declared: spec(60, 60),
		off: spec(60, 60),
		offConfigured: spec(60, 60),
	},
	"webauthn-authentication-options": {
		shipped: spec(30, 60),
		configured: spec(11, 30),
		declared: spec(9, 15),
		off: spec(60, 60),
		offConfigured: spec(60, 60),
	},
	mfa: {
		shipped: spec(60, 60),
		configured: spec(60, 60),
		declared: spec(6, 75),
		off: spec(60, 60),
		offConfigured: spec(60, 60),
	},
	token: {
		shipped: spec(60, 60),
		configured: spec(60, 60),
		declared: spec(17, 20),
		off: spec(60, 60),
		offConfigured: spec(60, 60),
	},
};

/** Each owner's own key, as an operator's layer sets it. */
const OWNERS_KEYS = `
session.rateLimit.login { windowMs = 60000, limit = 7 }
device-grant.rateLimit { limit = 3, windowSeconds = 120 }
webauthn.rateLimit.authenticationOptions { limit = 11, windowSeconds = 30 }
`;

/** The limiter's own section's name. */
const limiterSection = (adapter: Adapter): string =>
	adapter === "redis" ? "redis-rate-limiter" : "core-rate-limiter-memory";

/** Every prefix but a verifier's in the limiter's own section, beside the owners' keys. */
const declaredLimits = (adapter: Adapter): string => `
${limiterSection(adapter)}.limits {
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
	offConfigured: () => ({
		features: { deviceGrant: false, webauthn: false, mfa: false },
		operatorHocon: OWNERS_KEYS,
	}),
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
				ADAPTERS_RATE_LIMITER: "redis",
				REDIS_CLIENTS_URL: `redis://${redis.host}:${redis.port}/${redis.db}`,
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
	describe.each<Cell>(["shipped", "configured", "declared", "off", "offConfigured"])(
		"%s",
		(cell) => {
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
		},
	);
});

describe.each<Adapter>(["memory", "redis"])("the %s limiter's own limits", (adapter) => {
	it.each([
		["login", "session.rateLimit.login"],
		["device_verification", "device-grant.rateLimit"],
	])(
		"refuses the boot on an entry for %s, a verifier's own limit, naming the key and %s",
		async (prefix, setting) => {
			const err = await composeFullSet({
				env: envFor(adapter),
				operatorHocon: `${limiterSection(adapter)}.limits { ${prefix} { limit = 1000, windowSeconds = 1 } }`,
			}).then(
				(composition) => composition.handle.dispose().then(() => undefined),
				(caught: unknown) => caught,
			);

			expect(err).toBeInstanceOf(BootError);
			expect((err as BootError).reason).toBe("config-validation-failed");
			expect((err as BootError).message).toContain(`${limiterSection(adapter)}.limits.${prefix}`);
			expect((err as BootError).message).toContain(setting);
		},
	);

	it("refuses the boot on an entry for a prefix a module declares a verifier's, naming its setting", async () => {
		const declarer = defineModule({
			name: "test:verifier-declarer",
			contributes: {
				rateLimitBudgets: {
					"test-verifier": verifierLimitClaim({ setting: "test-verifier.attempts" }),
				},
			},
		});
		const options = await fullSetOptions({
			env: envFor(adapter),
			operatorHocon: `${limiterSection(adapter)}.limits { test-verifier { limit = 1000, windowSeconds = 1 } }`,
		});
		const err = await compose({
			...options,
			extraModules: (config) => [...(options.extraModules?.(config) ?? []), declarer],
		}).then(
			(composition) => composition.handle.dispose().then(() => undefined),
			(caught: unknown) => caught,
		);

		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("config-validation-failed");
		expect((err as BootError).message).toContain(`${limiterSection(adapter)}.limits.test-verifier`);
		expect((err as BootError).message).toContain("set test-verifier.attempts instead");
	});
});

/** Every prefix a package keys a limiter under, with the module that owns it. */
const KEYED = [
	["token", "oauth"],
	["authorize", "oauth"],
	["introspect", "oauth"],
	["revoke", "oauth"],
	["login", "session"],
	["device_authorization", "device-grant"],
	["device_verification", "device-grant"],
	["federation_grants", "federation-grants"],
	["federation_grants_browser", "federation-grants"],
	["webauthn-authentication-options", "webauthn"],
	["mfa", "mfa"],
] as const;

describe("a prefix is its owner's", () => {
	it.each(KEYED)(
		"refuses at boot a module that contributes a budget for %s, which %s claims",
		async (prefix, owner) => {
			const squatter = defineModule({
				name: "test:budget-squatter",
				contributes: {
					rateLimitBudgets: { [prefix]: () => ({ limit: 1_000_000, windowSeconds: 1 }) },
				},
			});
			const options = await fullSetOptions();
			const err = await compose({
				...options,
				extraModules: (config) => [...(options.extraModules?.(config) ?? []), squatter],
			}).then(
				(composition) => composition.handle.dispose().then(() => undefined),
				(caught: unknown) => caught,
			);

			expect(err).toBeInstanceOf(BootError);
			expect((err as BootError).reason).toBe("duplicate-contribute");
			expect((err as BootError).details).toMatchObject({
				kind: "rateLimitBudgets",
				identity: prefix,
				modules: [owner, "test:budget-squatter"],
			});
		},
	);
});

describe("the login's attempt limit at /session/login", () => {
	it("is session.rateLimit.login, counted per IP, and advertises nothing of it", async () => {
		const composition = await composeFullSet({
			operatorHocon: "session.rateLimit.login { windowMs = 60000, limit = 2 }",
		});
		try {
			expect((await login(composition.app)).res.status).toBe(200);
			expect((await login(composition.app)).res.status).toBe(200);
			const { res } = await login(composition.app);
			expect(res.status).toBe(429);
			expect(res.body.error).toBe("rate_limited");
			expect(Number(res.headers["retry-after"])).toBeGreaterThan(0);
			expect(Object.keys(res.headers).filter((h) => h.startsWith("ratelimit-"))).toEqual([]);
		} finally {
			await composition.handle.dispose();
		}
	});

	it("holds on the Redis counter, whatever the Redis limiter's failMode", async () => {
		const composition = await composeFullSet({
			env: {
				...envFor("redis"),
				ADAPTERS_ATTEMPT_COUNTER: "redis",
				REDIS_RATE_LIMITER_FAIL_MODE: "open",
			},
			operatorHocon: "session.rateLimit.login { windowMs = 60000, limit = 1 }",
		});
		try {
			expect(composition.handle.components.attemptCounter).toBeDefined();
			expect((await login(composition.app)).res.status).toBe(200);
			expect((await login(composition.app)).res.status).toBe(429);
		} finally {
			await composition.handle.dispose();
		}
	});
});
