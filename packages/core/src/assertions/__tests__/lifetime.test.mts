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
 * `assertionLifetime` — the one `exp` comparison both recorded-assertion
 * verifiers make (the ID-JAG registry verifier and `private_key_jwt`), so the
 * two cannot drift: at most `MAX_ASSERTION_LIFETIME_SECONDS` plus the
 * verifier's clock tolerance past now. Each verifier's use of it is pinned in
 * `idJagLifetime.test.mts` and oauth's `clientAssertion.test.mts`.
 */

import { describe, expect, it } from "vitest";
import { assertionLifetime, MAX_ASSERTION_LIFETIME_SECONDS } from "#/assertions/lifetime.mjs";

describe("assertionLifetime", () => {
	const now = 1_800_000_000;

	it("admits exp up to the ceiling plus the tolerance, the boundary included", () => {
		for (const ahead of [0, 29, 30]) {
			expect(assertionLifetime(now + MAX_ASSERTION_LIFETIME_SECONDS + ahead, now, 30)).toEqual({
				lifetimeSeconds: MAX_ASSERTION_LIFETIME_SECONDS + ahead,
				maxLifetimeSeconds: MAX_ASSERTION_LIFETIME_SECONDS + 30,
				exceeded: false,
			});
		}
	});

	it("refuses exp one second past the ceiling plus the tolerance", () => {
		expect(assertionLifetime(now + MAX_ASSERTION_LIFETIME_SECONDS + 31, now, 30)).toMatchObject({
			exceeded: true,
		});
		expect(assertionLifetime(now + MAX_ASSERTION_LIFETIME_SECONDS + 1, now, 0)).toMatchObject({
			exceeded: true,
		});
	});

	it("measures a fractional exp as it is", () => {
		expect(assertionLifetime(now + 60.5, now, 30)).toMatchObject({
			lifetimeSeconds: 60.5,
			exceeded: false,
		});
	});
});
