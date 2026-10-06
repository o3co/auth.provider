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
 * How long a subject's revocation boundary has to last. The **grants**
 * boundary must outlast every grant it could ever cover, and what bounds those
 * is a constant the code enforces at the write — not a configuration setting,
 * which an operator can lower, revoke under, and raise again. The
 * **sessions** boundary must outlast the sessions and tokens a cascade might
 * have missed, and what bounds those IS configuration.
 * See ADR 2026-09-17-federation-grants-offline-delegation.
 */

import { describe, expect, it } from "vitest";
import {
	ASSERTION_MAX_LIFETIME_LIMIT_SECONDS,
	MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS,
} from "#/assertions/lifetime.mjs";
import { MAX_DURATION_MS } from "#/config/durations.mjs";
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
			accessToken: { defaultExpiresIn: 3600 },
			...((over.oauth as Record<string, unknown>) ?? {}),
		},
		...over,
	});
	/** The session store's slot, carrying a session lifetime of `maxAgeMs`. */
	const session = (maxAgeMs: number) => ({ sessionCookie: { maxAgeMs } as never });

	it("outlasts the longest-lived thing a cascade could have missed", () => {
		// A refresh token of a day, in seconds; a session of twelve hours, in
		// milliseconds. Two units, which is the first thing this gets wrong.
		const horizon = resolveSubjectRevocationHorizonMs(config(), session(43_200_000));
		expect(horizon).toBeGreaterThan(86_400_000);
	});

	it("sizes the access token from the maximum a request may obtain, not the default", () => {
		// `expiresIn` is what a grant mints when the request asks for nothing;
		// token exchange may ask for more, up to `maxExpiresIn`. A horizon
		// computed from the default expires while those longer tokens are still
		// valid — and a token that outlives the boundary that revoked it works
		// again.
		const horizon = resolveSubjectRevocationHorizonMs(
			{
				oauth: {
					refreshToken: { expiresIn: 60 },
					accessToken: { defaultExpiresIn: 60, maxExpiresIn: 86_400 },
				},
			},
			session(60_000),
		);
		expect(horizon).toBeGreaterThan(86_400_000);
	});

	it("reads the deprecated alias where that is all a deployment has", () => {
		// `expiresIn` alone means both the default and the maximum.
		const horizon = resolveSubjectRevocationHorizonMs(
			{ oauth: { refreshToken: { expiresIn: 60 }, accessToken: { defaultExpiresIn: 172_800 } } },
			session(60_000),
		);
		expect(horizon).toBeGreaterThan(172_800_000);
		expect(horizon).toBeLessThan(172_800_000 + 600_000);
	});

	it("outlasts every assertion an issuer entry may accept, whatever the configured lifetimes", () => {
		// A jwt-bearer assertion issued before the boundary lives at most the
		// largest entry ceiling (`exp − iat`), and is accepted up to its entry's
		// clock tolerance past `exp`. The registry is not visible here, so the
		// limit stands in for the largest ceiling.
		const horizon = resolveSubjectRevocationHorizonMs(
			{ oauth: { refreshToken: { expiresIn: 60 }, accessToken: { defaultExpiresIn: 60 } } },
			session(60_000),
		);
		expect(horizon).toBeGreaterThan(
			(ASSERTION_MAX_LIFETIME_LIMIT_SECONDS + MAX_ASSERTION_CLOCK_TOLERANCE_SECONDS) * 1000,
		);
	});

	it("adds the tolerance with which those things are actually accepted", () => {
		// `verifyJwt` passes `clockTolerance`, so a token is accepted for five
		// minutes past its `exp`. A watermark sized to the nominal expiry leaves
		// exactly that window with no backstop behind it.
		const horizon = resolveSubjectRevocationHorizonMs(config(), session(43_200_000));
		expect(horizon).toBeGreaterThanOrEqual(86_400_000 + 300_000);
	});

	it("takes the session lifetime when it is the longer one", () => {
		const horizon = resolveSubjectRevocationHorizonMs(config(), session(30 * 86_400_000));
		expect(horizon).toBeGreaterThan(30 * 86_400_000);
	});

	it("takes the access-token maximum, which configuration does not bound by the refresh token", () => {
		// Nothing says an access token must be shorter than a refresh token.
		const horizon = resolveSubjectRevocationHorizonMs(
			config({
				oauth: { refreshToken: { expiresIn: 60 }, accessToken: { defaultExpiresIn: 86_400 } },
			}),
			session(43_200_000),
		);
		expect(horizon).toBeGreaterThanOrEqual(86_400_000 + 300_000);
	});

	it("refuses a configuration that does not say how long these things live", () => {
		// A hand-built configuration bypasses the schema, and a horizon
		// computed from a missing lifetime is a boundary that expires early.
		for (const broken of [
			{},
			config({
				oauth: { refreshToken: { expiresIn: "soon" }, accessToken: { defaultExpiresIn: 3600 } },
			}),
		]) {
			expect(
				() => resolveSubjectRevocationHorizonMs(broken, session(43_200_000)),
				JSON.stringify(broken),
			).toThrow();
		}
	});

	it("refuses to size a boundary without the session store's slot, naming it: core reads no session-store key", () => {
		for (const written of [config(), config({ "session-store": { maxAge: 43_200_000 } })]) {
			const call = () => resolveSubjectRevocationHorizonMs(written);
			expect(call, JSON.stringify(written)).toThrow(RangeError);
			expect(call, JSON.stringify(written)).toThrow("no sessionCookiePolicy was handed");
		}
	});

	describe("from the slots", () => {
		const tokenSettings = (over: Record<string, unknown> = {}) =>
			({
				accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 7_200 },
				refreshTokenExpiresIn: 3_600,
				...over,
			}) as never;
		const sessionCookie = (maxAgeMs: unknown) => ({ maxAgeMs }) as never;

		it("reads each lifetime from the slot that carries it, in place of the configuration's", () => {
			// The configuration says thirty days of refresh token; the slot says
			// an hour, and two days of access token. The slot is what was minted.
			const horizon = resolveSubjectRevocationHorizonMs(
				config({
					oauth: {
						refreshToken: { expiresIn: 30 * 86_400 },
						accessToken: { defaultExpiresIn: 3600 },
					},
				}),
				{
					tokenSettings: tokenSettings({
						accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 172_800 },
					}),
					sessionCookie: sessionCookie(60_000),
				},
			);
			expect(horizon).toBeGreaterThan(172_800_000);
			expect(horizon).toBeLessThan(30 * 86_400_000);
		});

		it("refuses a slot's value it cannot print as JSON with its RangeError, never a TypeError", () => {
			const circular: Record<string, unknown> = {};
			circular.self = circular;
			const cases: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(1n) }],
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(circular) }],
				[
					"oauthTokenSettings.refreshTokenExpiresIn",
					{ tokenSettings: tokenSettings({ refreshTokenExpiresIn: 1n }) },
				],
				[
					"oauthTokenSettings.accessTokenLifetime.maxExpiresIn",
					{
						tokenSettings: tokenSettings({
							accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: circular },
						}),
					},
				],
			];
			for (const [path, from] of cases) {
				const call = () => resolveSubjectRevocationHorizonMs(config(), from);
				expect(call, path).toThrow(RangeError);
				expect(call, path).toThrow(path);
			}
		});

		it("accepts a session lifetime at the one-year ceiling", () => {
			expect(
				resolveSubjectRevocationHorizonMs(config(), {
					sessionCookie: sessionCookie(MAX_DURATION_MS),
				}),
			).toBeGreaterThan(MAX_DURATION_MS);
		});

		it("holds a slot's lifetime to the rule the configuration's is held to, naming the slot", () => {
			// A slot built by hand meets no schema either. A zero or a string in
			// the arithmetic would size the boundary from nothing — or from NaN,
			// which retains nothing.
			const cases: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(0) }],
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(-1) }],
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(Number.NaN) }],
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie("12h") }],
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(undefined) }],
				// The session store's provider holds session-store.maxAge to whole
				// milliseconds within the one-year ceiling, as the schema does.
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(1.5) }],
				["sessionCookiePolicy.maxAgeMs", { sessionCookie: sessionCookie(MAX_DURATION_MS + 1) }],
				[
					"oauthTokenSettings.refreshTokenExpiresIn",
					{ tokenSettings: tokenSettings({ refreshTokenExpiresIn: 0 }) },
				],
				[
					"oauthTokenSettings.refreshTokenExpiresIn",
					{ tokenSettings: tokenSettings({ refreshTokenExpiresIn: "soon" }) },
				],
				[
					"oauthTokenSettings.refreshTokenExpiresIn",
					{ tokenSettings: tokenSettings({ refreshTokenExpiresIn: undefined }) },
				],
				[
					"oauthTokenSettings.accessTokenLifetime.maxExpiresIn",
					{
						tokenSettings: tokenSettings({
							accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 0 },
						}),
					},
				],
				[
					"oauthTokenSettings.accessTokenLifetime.maxExpiresIn",
					{
						tokenSettings: tokenSettings({
							accessTokenLifetime: { defaultExpiresIn: 60, maxExpiresIn: 1.5 },
						}),
					},
				],
				[
					"oauthTokenSettings.accessTokenLifetime.maxExpiresIn",
					{ tokenSettings: tokenSettings({ accessTokenLifetime: undefined }) },
				],
			];
			for (const [path, from] of cases) {
				const call = () => resolveSubjectRevocationHorizonMs(config(), from);
				const label = `${path} from ${JSON.stringify(from)}`;
				expect(call, label).toThrow(RangeError);
				expect(call, label).toThrow(path);
			}
		});
	});
});
