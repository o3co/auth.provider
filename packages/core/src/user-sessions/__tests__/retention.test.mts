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
 * How long a subject's revocation boundary has to last (#593, D13).
 *
 * Two answers, because there are two boundaries and they are bounded by
 * different things:
 *
 *  - the **grants** boundary must outlast every grant it could ever cover, and
 *    what bounds those is a constant the code enforces at the write — not a
 *    configuration setting, which an operator can lower, revoke under, and
 *    raise again;
 *  - the **sessions** boundary must outlast the sessions and tokens a cascade
 *    might have missed, and what bounds those IS configuration.
 */

import { describe, expect, it } from "vitest";
import { FEDERATION_GRANT_LIFETIME_CEILING_MS } from "#/federation-grants/lifetime.mjs";
import {
	resolveSubjectRevocationHorizonMs,
	SUBJECT_REVOCATION_MIN_RETENTION_MS,
} from "#/user-sessions/retention.mjs";

describe("SUBJECT_REVOCATION_MIN_RETENTION_MS", () => {
	it("outlasts the longest grant the code will ever allow, with a margin", () => {
		// The relation is the point, not the number: a grant cannot be
		// consented for longer than the ceiling (`activate` refuses it), and the
		// boundary is stamped no earlier than that consent, so the boundary
		// outlives every grant it covers whatever an operator does to the
		// configuration.
		expect(SUBJECT_REVOCATION_MIN_RETENTION_MS).toBe(FEDERATION_GRANT_LIFETIME_CEILING_MS + 60_000);
		expect(SUBJECT_REVOCATION_MIN_RETENTION_MS).toBeGreaterThan(
			FEDERATION_GRANT_LIFETIME_CEILING_MS,
		);
	});
});

describe("resolveSubjectRevocationHorizonMs", () => {
	const config = (over: Record<string, unknown> = {}) => ({
		oauth: {
			refreshToken: { expiresIn: 86_400 },
			accessToken: { expiresIn: 3600 },
			...((over.oauth as Record<string, unknown>) ?? {}),
		},
		session: { maxAge: 43_200_000 },
		...over,
	});

	it("outlasts the longest-lived thing a cascade could have missed", () => {
		// A refresh token of a day, in seconds; a session of twelve hours, in
		// milliseconds. Two units, which is the first thing this gets wrong.
		const horizon = resolveSubjectRevocationHorizonMs(config());
		expect(horizon).toBeGreaterThan(86_400_000);
	});

	it("adds the tolerance with which those things are actually accepted", () => {
		// `verifyJwt` passes `clockTolerance`, so a token is accepted for five
		// minutes past its `exp`. A watermark sized to the nominal expiry leaves
		// exactly that window with no backstop behind it.
		const horizon = resolveSubjectRevocationHorizonMs(config());
		expect(horizon).toBeGreaterThanOrEqual(86_400_000 + 300_000);
	});

	it("takes the session lifetime when it is the longer one", () => {
		const horizon = resolveSubjectRevocationHorizonMs(
			config({ session: { maxAge: 30 * 86_400_000 } }),
		);
		expect(horizon).toBeGreaterThan(30 * 86_400_000);
	});

	it("takes the access-token maximum, which configuration does not bound by the refresh token", () => {
		// Nothing says an access token must be shorter than a refresh token.
		const horizon = resolveSubjectRevocationHorizonMs(
			config({ oauth: { refreshToken: { expiresIn: 60 }, accessToken: { expiresIn: 86_400 } } }),
		);
		expect(horizon).toBeGreaterThanOrEqual(86_400_000 + 300_000);
	});

	it("refuses a configuration that does not say how long these things live", () => {
		// A hand-built configuration bypasses the schema (#448), and a horizon
		// computed from a missing lifetime is a boundary that expires early.
		for (const broken of [
			{ session: { maxAge: 43_200_000 } },
			{ oauth: { refreshToken: { expiresIn: 86_400 }, accessToken: { expiresIn: 3600 } } },
			config({ session: { maxAge: null } }),
			config({ oauth: { refreshToken: { expiresIn: "soon" }, accessToken: { expiresIn: 3600 } } }),
		]) {
			expect(() => resolveSubjectRevocationHorizonMs(broken), JSON.stringify(broken)).toThrow();
		}
	});
});
