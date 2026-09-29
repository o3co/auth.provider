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
import { TransitionalConfigSchema } from "#/config/composed.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * The sections core's schema still mirrors for another package's modules
 * (#728, transitional): `redisRateLimiter`, the `redis*` store namespaces,
 * `oauth.mtls`, `oauth.dpop`, `webauthn`. Boot's composed parse applies each
 * mirror whenever the configuration carries the section — the module that
 * reads it loaded or not — until the move pull request for its package takes
 * the mirror out of core's schema; the checks pinned here go with it.
 *
 * Nothing here is about a section surviving: boot lays every parse over what
 * was written, and a loaded module's section is written back at its path
 * (`boot/__tests__/composed-parse.test.mts`). What a mirror does is coerce an
 * environment variable's string, refuse a value by path, and stay absent
 * when the section is — the defaults live in each package's
 * `config/reference.conf`.
 */

const base = makeValidAppConfig();
const parse = (config: unknown) => TransitionalConfigSchema.parse(config);

describe("redisRateLimiter's mirror", () => {
	it("coerces the env-var spelling of a budget, like memoryRateLimiter", () => {
		const parsed = parse({
			...base,
			redisRateLimiter: { limits: { token: { limit: "120", windowSeconds: "60" } } },
		});
		expect(parsed.redisRateLimiter?.limits?.token).toEqual({ limit: 120, windowSeconds: 60 });
	});

	it("refuses a budget that would read as configured and limit nothing", () => {
		expect(() =>
			parse({ ...base, redisRateLimiter: { defaultLimit: { limit: 0, windowSeconds: 60 } } }),
		).toThrow();
	});

	it("refuses a window longer than a year, the ceiling of every duration an operator writes", () => {
		// A typo guard: 1e13 seconds is a window no Redis key can carry and no
		// Date can end, and the adapter refusing it at boot is the second line.
		for (const section of ["redisRateLimiter", "memoryRateLimiter"] as const) {
			for (const spec of [
				{ defaultLimit: { limit: 5, windowSeconds: 31_536_001 } },
				{ limits: { token: { limit: 5, windowSeconds: 1e13 } } },
			]) {
				expect(
					() => parse({ ...base, [section]: spec }),
					`${section} ${JSON.stringify(spec)}`,
				).toThrow();
			}
			expect(
				parse({ ...base, [section]: { defaultLimit: { limit: 5, windowSeconds: 31_536_000 } } })[
					section
				]?.defaultLimit,
			).toEqual({ limit: 5, windowSeconds: 31_536_000 });
		}
	});

	it("is absent when omitted — the default lives in the module", () => {
		expect(parse(base).redisRateLimiter).toBeUndefined();
	});
});

describe("redisFederationGrantStore's listing allowance", () => {
	it("is held to a year, the ceiling of every duration an operator writes", () => {
		// Past the Date range it is a deadline Redis refuses after the script
		// has reserved the grant in its subject's index, which is left with no
		// TTL; the store refuses it too, as the second line.
		const allowance = (listingAllowanceMs: unknown) =>
			parse({ ...base, redisFederationGrantStore: { listingAllowanceMs } })
				.redisFederationGrantStore?.listingAllowanceMs;
		expect(allowance(31_536_000_000)).toBe(31_536_000_000);
		for (const value of [31_536_000_001, 1e21]) {
			expect(() => allowance(value), String(value)).toThrow();
		}
	});
});

describe("oauth.mtls's mirror", () => {
	it("coerces the env-var spelling of enabled (#288)", () => {
		const parsed = parse({ ...base, oauth: { ...base.oauth, mtls: { enabled: "true" } } });
		expect(parsed.oauth.mtls?.enabled).toBe(true);
	});

	it("refuses a trust posture the module does not have", () => {
		expect(() => parse({ ...base, oauth: { ...base.oauth, mtls: { mode: "pki-ish" } } })).toThrow();
	});

	it("is absent when omitted — the defaults live in the mtls reference.conf", () => {
		expect(parse(base).oauth.mtls).toBeUndefined();
	});
});

describe("oauth.dpop's mirror", () => {
	it("coerces the env-var spelling of enabled (#288)", () => {
		const parsed = parse({ ...base, oauth: { ...base.oauth, dpop: { enabled: "1" } } });
		expect(parsed.oauth.dpop?.enabled).toBe(true);
	});

	it("refuses the retired replay-store key, whatever it says, naming what replaced it", () => {
		// DPoP proofs are recorded in the `replaySeenSet` slot now, and the
		// key's two readings — a per-process fallback, or a mandatory
		// `dpopReplayStore` slot — no longer exist. Ignored, a deployment that
		// had wired a shared DPoP store beside a memory seen-set would move
		// its DPoP records into memory with no new signal.
		for (const value of ["memory", "redis"]) {
			const result = TransitionalConfigSchema.safeParse({
				...base,
				oauth: { ...base.oauth, dpop: { enabled: true, "replay-store": value } },
			});
			expect(result.success).toBe(false);
			const issue = result.success
				? undefined
				: result.error.issues.find((i) => i.path.join(".") === "oauth.dpop.replay-store");
			expect(issue?.message).toMatch(/^oauth\.dpop\.replay-store was removed in /);
			expect(issue?.message).toMatch(/replaySeenSet/);
			expect(issue?.message).toMatch(/Remove this field from your config\.$/);
		}
	});

	it("is absent when omitted — the defaults live in the dpop reference.conf", () => {
		expect(parse(base).oauth.dpop).toBeUndefined();
	});
});

describe("webauthn's mirror", () => {
	it("keeps the single-origin spelling an env substitution produces, for the package's schema to split", () => {
		const parsed = parse({
			...base,
			webauthn: { origin: "https://example.com", topOrigin: "https://embedder.example" },
		});
		expect(parsed.webauthn?.origin).toBe("https://example.com");
		expect(parsed.webauthn?.topOrigin).toBe("https://embedder.example");
	});

	it("refuses a user-verification requirement WebAuthn does not have", () => {
		expect(() => parse({ ...base, webauthn: { userVerification: "optional" } })).toThrow();
	});

	it("is absent when omitted — the defaults live in the webauthn reference.conf", () => {
		expect(parse(base).webauthn).toBeUndefined();
	});
});
