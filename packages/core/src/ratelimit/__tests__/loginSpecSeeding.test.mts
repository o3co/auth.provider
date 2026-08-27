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

	it("does not seed when the config carries no usable login spec", () => {
		// A hand-built config that never passed the schema: better to leave the
		// adapter's own default in place than to invent a limit.
		expect(resolveLoginLimitSpec({}, {}).login).toBeUndefined();
		expect(
			resolveLoginLimitSpec({}, { rateLimit: { login: { windowMs: 0, limit: 20 } } }).login,
		).toBeUndefined();
		expect(
			resolveLoginLimitSpec({}, { rateLimit: { login: { windowMs: 900_000, limit: 0 } } }).login,
		).toBeUndefined();
	});
});
