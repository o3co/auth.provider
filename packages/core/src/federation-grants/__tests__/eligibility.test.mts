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
import {
	federationGrantIneligibilityRetry,
	federationGrantRefreshFailureStands,
	federationGrantIneligibilityStands,
	isUsableMaxUpstreamAccessTokenLifetime,
	judgeUpstreamAccessToken,
	resolveFederationGrantIntentScopes,
	scopesWithin,
} from "#/federation-grants/eligibility.mjs";
import type { FederationGrantRefreshFailure } from "#/federation-grants/types.mjs";

const CONSENTED = ["openid", "offline_access", "calendar.read"];

describe("upstream token eligibility (#593, D5)", () => {
	describe("judgeUpstreamAccessToken", () => {
		// No default parameter: passing `undefined` has to reach the rule.
		const judge = (
			token: { issuedLifetime: number | null; scopes: readonly string[] },
			...max: [maxAccessTokenLifetime?: number]
		) =>
			judgeUpstreamAccessToken({
				...token,
				consentedScopes: CONSENTED,
				maxAccessTokenLifetime: max.length === 0 ? 3600 : (max[0] as number),
			});

		it("accepts a finite lifetime within the maximum, carrying consented scopes", () => {
			expect(judge({ issuedLifetime: 3600, scopes: ["openid", "calendar.read"] })).toEqual({
				eligible: true,
			});
		});

		it("refuses a token with no finite lifetime: residual access would have no bound", () => {
			for (const bad of [null, 0, -5, Number.NaN, Number.POSITIVE_INFINITY]) {
				expect(judge({ issuedLifetime: bad, scopes: CONSENTED })).toEqual({
					eligible: false,
					reason: "no_finite_lifetime",
				});
			}
		});

		it("refuses a lifetime over the maximum: finite alone would admit a 30-day token", () => {
			expect(judge({ issuedLifetime: 3601, scopes: CONSENTED })).toEqual({
				eligible: false,
				reason: "lifetime_over_maximum",
			});
		});

		it("refuses every token when the maximum is not a usable number", () => {
			// A hand-built config that omits the key hands `undefined` through a
			// cast, and `lifetime > undefined` is false: a 30-day token would pass.
			// Infinity is no maximum either: every finite lifetime is within it,
			// and residual access would be a number nobody chose (D15).
			for (const bad of [
				Number.NaN,
				undefined as unknown as number,
				0,
				-1,
				Number.POSITIVE_INFINITY,
			]) {
				expect(judge({ issuedLifetime: 2_592_000, scopes: CONSENTED }, bad)).toEqual({
					eligible: false,
					reason: "lifetime_over_maximum",
				});
				expect(judge({ issuedLifetime: 60, scopes: CONSENTED }, bad)).toEqual({
					eligible: false,
					reason: "lifetime_over_maximum",
				});
			}
		});

		it("judges the lifetime the token was issued with, which does not shrink as it ages", () => {
			// A cached 3600 s token must not become disclosable merely by ageing
			// below a maximum the operator lowered to 1800 s.
			expect(judge({ issuedLifetime: 3600, scopes: CONSENTED }, 1800)).toEqual({
				eligible: false,
				reason: "lifetime_over_maximum",
			});
		});

		it("refuses scopes beyond the consent: an upstream token cannot be narrowed afterwards", () => {
			expect(judge({ issuedLifetime: 3600, scopes: [...CONSENTED, "files.readwrite"] })).toEqual({
				eligible: false,
				reason: "scope_exceeded",
			});
		});

		it("reports the unbounded lifetime first when several rules fail", () => {
			expect(judge({ issuedLifetime: null, scopes: ["files.readwrite"] })).toEqual({
				eligible: false,
				reason: "no_finite_lifetime",
			});
		});
	});

	describe("isUsableMaxUpstreamAccessTokenLifetime", () => {
		it("is a positive finite number of seconds, and nothing else", () => {
			expect(isUsableMaxUpstreamAccessTokenLifetime(1)).toBe(true);
			expect(isUsableMaxUpstreamAccessTokenLifetime(3600)).toBe(true);
			for (const bad of [
				Number.NaN,
				undefined as unknown as number,
				"3600" as unknown as number,
				0,
				-1,
				Number.POSITIVE_INFINITY,
			]) {
				expect(isUsableMaxUpstreamAccessTokenLifetime(bad)).toBe(false);
			}
		});
	});

	describe("scopesWithin", () => {
		it("compares names exactly", () => {
			expect(scopesWithin(["calendar.read"], CONSENTED)).toBe(true);
			expect(scopesWithin([], CONSENTED)).toBe(true);
			expect(scopesWithin(["Calendar.Read"], CONSENTED)).toBe(false);
			expect(scopesWithin(["calendar.read "], CONSENTED)).toBe(false);
			expect(scopesWithin(["https://graph.example/calendar.read"], CONSENTED)).toBe(false);
		});
	});

	describe("the ineligibility marker", () => {
		const at = new Date("2026-09-18T00:00:00.000Z");
		const marker = { reason: "lifetime_over_maximum" as const, at, judgedAgainst: 1800 };
		const later = (ms: number) => new Date(at.getTime() + ms);

		describe("federationGrantIneligibilityStands — what the status route reports", () => {
			it("stands for as long as the maximum it was judged against is the current one", () => {
				expect(federationGrantIneligibilityStands(marker, 1800)).toBe(true);
			});

			it("is void once that maximum has changed: the operator's fix must not wait", () => {
				expect(federationGrantIneligibilityStands(marker, 3600)).toBe(false);
			});

			it("does not lapse with time: only an eligible refresh, a reauthorization or that change clears it", () => {
				// The retry interval limits how often `/token` tries again. It says
				// nothing about whether the grant can yield a token, so it must not
				// turn the status back to `active`.
				expect(
					federationGrantIneligibilityStands({ ...marker, at: later(-86_400_000) }, 1800),
				).toBe(true);
			});

			it("is false when there is no marker", () => {
				expect(federationGrantIneligibilityStands(undefined, 1800)).toBe(false);
			});

			it("stands while the current maximum is one no token can satisfy: nothing has been fixed", () => {
				// A maximum that differs from `judgedAgainst` voids the marker because
				// the operator may have fixed the setting. An unusable one fixes
				// nothing — every token is refused under it — and `NaN === NaN` is
				// false, so a marker judged against NaN would never stand, and the
				// grant would refresh on every call again.
				for (const bad of [
					Number.NaN,
					undefined as unknown as number,
					0,
					-1,
					Number.POSITIVE_INFINITY,
				]) {
					expect(federationGrantIneligibilityStands(marker, bad)).toBe(true);
					expect(federationGrantIneligibilityStands({ ...marker, judgedAgainst: bad }, bad)).toBe(
						true,
					);
				}
			});
		});

		describe("federationGrantIneligibilityRetry — whether /token may call the upstream again", () => {
			const retry = (now: Date, retryAfterMs = 300_000) =>
				federationGrantIneligibilityRetry(marker, { now, retryAfterMs, allowanceMs: 30_000 });

			it("is not due until the interval has passed, so a starved grant does not refresh on every call", () => {
				expect(retry(later(0))).toEqual({ due: false, retryAfterSeconds: 300 });
				expect(retry(later(299_000))).toEqual({ due: false, retryAfterSeconds: 1 });
				expect(retry(later(300_000))).toEqual({ due: true });
			});

			it("rounds the wait up, so a client is never told to retry in zero seconds", () => {
				expect(retry(later(299_500))).toEqual({ due: false, retryAfterSeconds: 1 });
				expect(retry(later(298_001))).toEqual({ due: false, retryAfterSeconds: 2 });
			});

			it("does not believe a marker dated further ahead than the allowance: it would stand until its date caught up, whatever the client was told", () => {
				// The marker is outside the authenticated envelope: whoever can write
				// the record can date it in the future. Clamping only what the client
				// is TOLD would leave the marker standing for a day.
				const retryOf = (ahead: number) =>
					federationGrantIneligibilityRetry(
						{ ...marker, at: later(ahead) },
						{ now: at, retryAfterMs: 300_000, allowanceMs: 30_000 },
					);
				expect(retryOf(86_400_000)).toEqual({ due: true });
				expect(retryOf(30_001)).toEqual({ due: true });
				// Within the allowance it is believed, and the wait is still never
				// longer than the interval.
				expect(retryOf(30_000)).toEqual({ due: false, retryAfterSeconds: 300 });
			});

			it("is due when the arithmetic is not: the eligibility rule still guards the disclosure", () => {
				expect(retry(new Date(Number.NaN))).toEqual({ due: true });
				expect(retry(later(1_000), Number.NaN)).toEqual({ due: true });
				expect(
					federationGrantIneligibilityRetry(
						{ ...marker, at: new Date(Number.NaN) },
						{ now: at, retryAfterMs: 300_000, allowanceMs: 30_000 },
					),
				).toEqual({ due: true });
			});

			it("is due when there is no marker", () => {
				expect(
					federationGrantIneligibilityRetry(undefined, {
						now: at,
						retryAfterMs: 300_000,
						allowanceMs: 30_000,
					}),
				).toEqual({ due: true });
			});
		});
	});

	describe("the stamp of a failed refresh (D12)", () => {
		const at = new Date("2026-09-18T00:00:00.000Z");
		const later = (ms: number) => new Date(at.getTime() + ms);
		const limits = { allowanceMs: 30_000, backoffMs: 30_000, ceilingMs: 300_000 };
		const stamp = (
			over: Partial<FederationGrantRefreshFailure> = {},
		): FederationGrantRefreshFailure => ({
			at,
			kind: "unavailable",
			count: 1,
			...over,
		});
		const standing = (failure: FederationGrantRefreshFailure | undefined, now: Date) =>
			federationGrantRefreshFailureStands(failure, { now, ...limits });

		it("does not stand for the first outage: the next poll is the prompt retry an IdP's grace window takes", () => {
			expect(standing(stamp(), at)).toEqual({ stands: false });
			expect(standing(stamp(), later(1))).toEqual({ stands: false });
		});

		it("stands for the backoff from the second outage in a row", () => {
			expect(standing(stamp({ count: 2 }), at)).toEqual({
				stands: true,
				kind: "unavailable",
				retryAfterSeconds: 30,
			});
			expect(standing(stamp({ count: 2 }), later(29_999))).toEqual({
				stands: true,
				kind: "unavailable",
				retryAfterSeconds: 1,
			});
			expect(standing(stamp({ count: 2 }), later(30_000))).toEqual({ stands: false });
			expect(standing(stamp({ count: 9 }), later(29_999))).toMatchObject({ stands: true });
		});

		it("stands for the upstream's advice after a rate limit, never for less than the backoff nor for more than the ceiling", () => {
			expect(standing(stamp({ kind: "rate_limited" }), at)).toMatchObject({
				stands: true,
				kind: "rate_limited",
				retryAfterSeconds: 30,
			});
			expect(standing(stamp({ kind: "rate_limited", retryAfterSeconds: 120 }), at)).toMatchObject({
				retryAfterSeconds: 120,
			});
			expect(
				standing(stamp({ kind: "rate_limited", retryAfterSeconds: 120 }), later(120_000)),
			).toEqual({
				stands: false,
			});
			expect(standing(stamp({ kind: "rate_limited", retryAfterSeconds: 3600 }), at)).toMatchObject({
				retryAfterSeconds: 300,
			});
			expect(
				standing(stamp({ kind: "rate_limited", retryAfterSeconds: 3600 }), later(300_000)),
			).toEqual({
				stands: false,
			});
		});

		it("stands for the ceiling after a refusal: a configuration fault is the marker's class of problem", () => {
			expect(standing(stamp({ kind: "rejected" }), at)).toEqual({
				stands: true,
				kind: "rejected",
				retryAfterSeconds: 300,
			});
			expect(standing(stamp({ kind: "rejected" }), later(300_000))).toEqual({ stands: false });
		});

		it("rounds the wait up: a client is never told to retry in zero seconds", () => {
			expect(standing(stamp({ kind: "rejected" }), later(299_500))).toMatchObject({
				retryAfterSeconds: 1,
			});
		});

		it("does not believe a stamp dated further ahead than the allowance, nor one that is not a date, nor stand for none", () => {
			expect(standing(stamp({ kind: "rejected", at: later(30_001) }), at)).toEqual({
				stands: false,
			});
			expect(standing(stamp({ kind: "rejected", at: later(30_000) }), at)).toMatchObject({
				stands: true,
				retryAfterSeconds: 300,
			});
			expect(standing(stamp({ kind: "rejected", at: new Date(Number.NaN) }), at)).toEqual({
				stands: false,
			});
			expect(standing(stamp({ kind: "rejected" }), new Date(Number.NaN))).toEqual({
				stands: false,
			});
			expect(standing(undefined, at)).toEqual({ stands: false });
		});
	});
});

describe("the scopes of an intent (#593, D6)", () => {
	const connection = { scopes: CONSENTED };
	const resolve = resolveFederationGrantIntentScopes;

	it("is the connection's full set when the intent asks for nothing", () => {
		expect(resolve(undefined, connection)).toEqual({ ok: true, scopes: CONSENTED });
	});

	it("accepts a subset that keeps openid and offline_access, in the connection's order", () => {
		expect(resolve(["offline_access", "openid"], connection)).toEqual({
			ok: true,
			scopes: ["openid", "offline_access"],
		});
	});

	it("refuses a scope the connection does not list", () => {
		expect(resolve(["openid", "offline_access", "files.read"], connection)).toEqual({
			ok: false,
			reason: "outside_connection",
		});
	});

	it("refuses a subset without openid: the adapter requires an id_token", () => {
		expect(resolve(["offline_access", "calendar.read"], connection)).toEqual({
			ok: false,
			reason: "required_scope_missing",
		});
	});

	it("refuses a subset that drops offline_access where the connection lists it", () => {
		expect(resolve(["openid", "calendar.read"], connection)).toEqual({
			ok: false,
			reason: "required_scope_missing",
		});
		// A connection that does not list it cannot require it.
		expect(resolve(["openid"], { scopes: ["openid", "calendar.read"] })).toEqual({
			ok: true,
			scopes: ["openid"],
		});
	});

	it("refuses any subset on a connection that does not allow them, and accepts the full set there", () => {
		const strict = { scopes: CONSENTED, allowScopeSubsets: false };
		expect(resolve(["openid", "offline_access"], strict)).toEqual({
			ok: false,
			reason: "subsets_not_allowed",
		});
		expect(resolve([...CONSENTED].reverse(), strict)).toEqual({ ok: true, scopes: CONSENTED });
		expect(resolve(undefined, strict)).toEqual({ ok: true, scopes: CONSENTED });
	});

	it("drops duplicates, and refuses an empty request", () => {
		expect(resolve(["openid", "openid", "offline_access"], connection)).toEqual({
			ok: true,
			scopes: ["openid", "offline_access"],
		});
		expect(resolve([], connection)).toEqual({ ok: false, reason: "required_scope_missing" });
	});

	it("applies one rule however the full set is asked for: a connection without openid yields no intent", () => {
		// Absent, explicit, or forced by `allowScopeSubsets = false` — the same
		// set must get the same answer. The package refuses such a connection at
		// boot; this is what stands behind that.
		const noOpenid = { scopes: ["calendar.read"] };
		const refused = { ok: false, reason: "required_scope_missing" };
		expect(resolve(undefined, noOpenid)).toEqual(refused);
		expect(resolve(["calendar.read"], noOpenid)).toEqual(refused);
		expect(resolve(undefined, { ...noOpenid, allowScopeSubsets: false })).toEqual(refused);
		expect(resolve(undefined, { scopes: [] })).toEqual(refused);
	});
});
