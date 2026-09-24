/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * Issue #270 — `/session/login` now runs on the shared `RateLimiter`, keyed
 * `login:ip:<ip>`. An adapter resolves a spec by key prefix from its own
 * `limits` map, but the documented login window and limit live at
 * `config.rateLimit.login`. Without seeding, a `login:` key would fall through
 * to the adapter's `defaultLimit` of 60/60s — silently weaker than the
 * documented 20 / 15 min, and weaker in the direction that matters on a
 * password endpoint.
 */

import { describe, expect, it } from "vitest";
import { resolveLoginLimitSpec } from "#/ratelimit/loginSpec.mjs";

describe("resolveLoginLimitSpec", () => {
	it("seeds login from config.rateLimit.login when the adapter declares none", () => {
		const limits = resolveLoginLimitSpec(
			{},
			{ rateLimit: { login: { windowMs: 900_000, limit: 20 } } },
		);
		expect(limits.login).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("leaves an operator-declared login spec alone", () => {
		// An explicit `limits.login` is a statement about this adapter; seeding
		// over it would silently discard what the operator wrote.
		const limits = resolveLoginLimitSpec(
			{ login: { limit: 5, windowSeconds: 60 } },
			{ rateLimit: { login: { windowMs: 900_000, limit: 20 } } },
		);
		expect(limits.login).toEqual({ limit: 5, windowSeconds: 60 });
	});

	it("preserves every other prefix untouched", () => {
		const limits = resolveLoginLimitSpec(
			{ token: { limit: 100, windowSeconds: 60 } },
			{ rateLimit: { login: { windowMs: 900_000, limit: 20 } } },
		);
		expect(limits.token).toEqual({ limit: 100, windowSeconds: 60 });
		expect(limits.login).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("rounds a sub-second window up to one second", () => {
		// `windowMs` is milliseconds and specs are whole seconds; rounding down
		// would produce 0, and a zero window is not a window.
		const limits = resolveLoginLimitSpec({}, { rateLimit: { login: { windowMs: 500, limit: 3 } } });
		expect(limits.login).toEqual({ limit: 3, windowSeconds: 1 });
	});

	it("does not seed when the config does not give rateLimit.login at all", () => {
		// Absent: a config without the section, or without the key. The
		// adapter's own default applies, as #270 intends.
		expect(resolveLoginLimitSpec({}, {}).login).toBeUndefined();
		expect(resolveLoginLimitSpec({}, { rateLimit: {} }).login).toBeUndefined();
		expect(resolveLoginLimitSpec({}, { rateLimit: { failMode: "open" } }).login).toBeUndefined();
	});

	it("refuses a rateLimit.login that is given but unusable, naming the key", () => {
		// A hand-built config that never passed the schema is still a
		// configuration someone wrote. Skipped, the route ran on the adapter's
		// 60 per 60 s default instead of it; judged by the one predicate every
		// limiter uses, it is refused under its own name.
		for (const login of [
			{ windowMs: 0, limit: 20 },
			{ windowMs: 900_000, limit: 0 },
			{ windowMs: 1e19, limit: 20 },
			{ windowMs: 900_000, limit: 1.5 },
			{ windowMs: Number.NaN, limit: 20 },
			{ windowMs: -900_000, limit: 20 },
			{ windowMs: 900_000, limit: "twenty" },
			{ windowMs: 900_000, limit: "" },
			{ windowMs: "  ", limit: 20 },
			{ windowMs: 900_000, limit: true },
			{ windowMs: [900_000], limit: 20 },
			{ windowMs: 900_000, limit: "1.5" },
			null,
			"20/900000",
		]) {
			expect(
				() => resolveLoginLimitSpec({}, { rateLimit: { login } }),
				JSON.stringify(login),
			).toThrow(/^rateLimit\.login must be/);
		}
	});

	it("reads the key as its schema does: a numeric string is its number", () => {
		// HOCON substitutes an environment variable as a string, and
		// CoreConfigSchema's `z.coerce.number()` takes it. A seed handed the
		// same config without that parse must read it the same way, or a
		// value the schema accepts refuses to boot.
		expect(
			resolveLoginLimitSpec({}, { rateLimit: { login: { windowMs: "900000", limit: "20" } } })
				.login,
		).toEqual({ limit: 20, windowSeconds: 900 });
		expect(
			resolveLoginLimitSpec({}, { rateLimit: { login: { windowMs: 900_000, limit: " 20 " } } })
				.login,
		).toEqual({ limit: 20, windowSeconds: 900 });
	});

	it("says what it was given, with each value's type", () => {
		// `String()` printed "limit 20" for the string "20", which read as a
		// refusal of a usable number.
		expect(() =>
			resolveLoginLimitSpec({}, { rateLimit: { login: { windowMs: 900_000, limit: "twenty" } } }),
		).toThrow(/\(got windowMs 900000, limit "twenty"\)$/);
		expect(() =>
			resolveLoginLimitSpec({}, { rateLimit: { login: { windowMs: true, limit: 20 } } }),
		).toThrow(/\(got windowMs true, limit 20\)$/);
	});
});
