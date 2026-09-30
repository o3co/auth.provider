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
import { TransitionalConfigSchema } from "#/config/composed.mjs";
import { makeValidAppConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * The sections core's schema still mirrors, transitionally, for another
 * package's modules: `redisRateLimiter`, the `redis*` store namespaces,
 * `webauthn`. Boot's composed parse applies each
 * mirror whenever the configuration carries the section, the module that
 * reads it loaded or not; a check here goes when its mirror leaves core.
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

describe("the paths the dpop, mtls, device-grant and oauth-token-exchange sections moved from", () => {
	// A root that parses with `AppConfigSchema` before boot hands what it kept
	// to the relocation refusal; the schema checks nothing under them.
	it.each([
		["dpop", { enabled: "not-a-boolean", "replay-store": "redis", nonce: { secret: "x" } }],
		["mtls", { mode: "pki-ish", "cert-header": "x-client-cert" }],
		["deviceAuthorization", { store: "memory", rateLimit: { limit: 5, windowSeconds: 1e13 } }],
		["tokenExchange", { maxActorChainDepth: "not-a-number" }],
	])("keeps oauth.%s as written", (key, written) => {
		const parsed = parse({ ...base, oauth: { ...base.oauth, [key]: written } });
		expect((parsed.oauth as Record<string, unknown>)[key]).toEqual(written);
		expect(
			(
				AppConfigSchema.parse({ ...base, oauth: { ...base.oauth, [key]: written } })
					.oauth as Record<string, unknown>
			)[key],
		).toEqual(written);
	});

	it.each(["dpop", "mtls", "deviceAuthorization", "tokenExchange"])(
		"is absent when oauth.%s is",
		(key) => {
			expect(parse(base).oauth).not.toHaveProperty(key);
		},
	);
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
