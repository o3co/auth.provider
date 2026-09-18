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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	assertFederationGrantRetrievalLimits,
	retrieveFederationGrantToken,
} from "#/federation-grants/retrieve.mjs";
import {
	at,
	type Harness,
	HOUR,
	harness,
	limits,
	MIN,
	now,
	refreshed,
	request,
	SECRET,
	setNow,
	T0,
} from "./retrieve.harness.mjs";

/**
 * A refresh that failed is remembered on the record (D12): while the stamp
 * stands the upstream is not asked, a stored token that serves is answered as
 * it is, and otherwise the failure is, with how long to wait. Without the
 * stamp every request that needs a refresh asks a failing upstream again, and
 * N polls during an incident are N upstream calls.
 */
describe("retrieveFederationGrantToken — a failed refresh is remembered (#593, D12)", () => {
	let h: Harness;

	beforeEach(() => {
		vi.useFakeTimers();
		setNow(T0);
		h = harness();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	const retrieve = (over: Partial<typeof request> = {}) =>
		retrieveFederationGrantToken(h.deps, { ...request, ...over });

	/** The seeded token has just run out: nothing that is stored serves a request any more. */
	const GONE = at(HOUR);
	const outage = () => Object.assign(new Error("x"), { status: 503 });
	const stamp = async () => (await h.store.find("g-1", now()))?.refreshFailure;

	describe("an outage", () => {
		it("is retried promptly once — the next poll is the retry an IdP's grace window takes — and remembered from the second time on", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(outage());
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "upstream",
			});
			expect(await stamp()).toMatchObject({ kind: "unavailable", count: 1 });

			// The prompt retry: asked again at once.
			setNow(new Date(now().getTime() + 1_000));
			expect(await retrieve()).toMatchObject({ code: "temporarily_unavailable" });
			expect(h.refresh).toHaveBeenCalledTimes(2);
			expect(await stamp()).toMatchObject({ count: 2 });

			// Then not, for the backoff: the stamp answers, with how long to wait.
			for (let i = 0; i < 5; i++) {
				setNow(new Date(now().getTime() + 5_000));
				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "temporarily_unavailable",
					reason: "upstream",
					retryAfterSeconds: 30 - 5 * (i + 1),
				});
			}
			expect(h.refresh).toHaveBeenCalledTimes(2);

			// And asked again once it has passed.
			setNow(new Date(now().getTime() + 5_000));
			await retrieve();
			expect(h.refresh).toHaveBeenCalledTimes(3);
			expect(await stamp()).toMatchObject({ count: 3 });
		});

		it("costs N concurrent polls one upstream call, not N: the stamp is written under the lock, and every waiter finds it", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockImplementation(
				() =>
					new Promise((_, reject) => {
						setTimeout(() => reject(outage()), 200);
					}),
			);
			const first = retrieve();
			await vi.advanceTimersByTimeAsync(300);
			await first;
			expect(await stamp()).toMatchObject({ count: 1 });

			const polls = [1, 2, 3, 4].map((n) => retrieve({ correlationId: `req-${n}` }));
			await vi.advanceTimersByTimeAsync(4 * limits.lockWaitMs);
			for (const answer of await Promise.all(polls)) {
				expect(answer).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
			}
			// The first poll's prompt retry, and nothing for the three that waited.
			expect(h.refresh).toHaveBeenCalledTimes(2);
		});

		it("does not withhold a stored token that serves: the stamp says only that the upstream is not asked", async () => {
			await h.seed();
			setNow(at(40 * MIN));
			h.refresh.mockRejectedValue(outage());
			await retrieve({ minTtlSeconds: 3000 });
			await retrieve({ minTtlSeconds: 3000 });
			expect(await stamp()).toMatchObject({ count: 2 });
			expect(await retrieve({ minTtlSeconds: 3000 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
				refreshed: false,
			});
			expect(h.refresh).toHaveBeenCalledTimes(2);
		});

		it("is the first of its row again once the last one is older than the ceiling: a day-old stamp does not cost today's outage its prompt retry", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(outage());
			await retrieve();
			expect(await stamp()).toMatchObject({ count: 1 });
			setNow(new Date(now().getTime() + limits.ineligibleRetryAfterMs + 1));
			await retrieve();
			expect(await stamp()).toMatchObject({ count: 1 });
			// And retried promptly, as the first of a row is.
			await retrieve();
			expect(h.refresh).toHaveBeenCalledTimes(3);
		});

		it("is forgotten by a refresh that wrote: the count starts over", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValueOnce(outage()).mockRejectedValueOnce(outage());
			await retrieve();
			await retrieve();
			setNow(new Date(now().getTime() + limits.refreshFailureBackoffMs));
			h.refresh.mockResolvedValueOnce(refreshed("1", now()));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1" });
			expect(await stamp()).toBeUndefined();

			// An hour on, an outage is the first of its row again: retried promptly.
			setNow(new Date(now().getTime() + HOUR));
			h.refresh.mockRejectedValue(outage());
			await retrieve();
			expect(await stamp()).toMatchObject({ count: 1 });
			await retrieve();
			expect(h.refresh).toHaveBeenCalledTimes(5);
		});
	});

	describe("a rate limit", () => {
		it("is remembered at once, for the upstream's advice: a 429 was not processed, and there is nothing to recover promptly", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(
				Object.assign(new Error("x"), {
					status: 429,
					response: new Response(null, { status: 429, headers: { "retry-after": "120" } }),
				}),
			);
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "rate_limited",
				reason: "upstream",
				retryAfterSeconds: 120,
			});
			expect(await stamp()).toMatchObject({ kind: "rate_limited", retryAfterSeconds: 120 });
			setNow(new Date(now().getTime() + 30_000));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "rate_limited",
				reason: "upstream",
				retryAfterSeconds: 90,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
			setNow(new Date(now().getTime() + 90_000));
			await retrieve();
			expect(h.refresh).toHaveBeenCalledTimes(2);
		});

		it("tells the failing caller no more than it tells the next: the advice is capped at the ceiling for both", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(
				Object.assign(new Error("x"), {
					status: 429,
					response: new Response(null, { status: 429, headers: { "retry-after": "3600" } }),
				}),
			);
			expect(await retrieve()).toMatchObject({ code: "rate_limited", retryAfterSeconds: 300 });
			expect(await retrieve({ correlationId: "req-2" })).toMatchObject({
				code: "rate_limited",
				retryAfterSeconds: 300,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});

		it("is remembered for the backoff at least, when the upstream gave no advice", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(Object.assign(new Error("x"), { status: 429 }));
			// The failing caller is told what the next one is: the stamp answers both.
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "rate_limited",
				reason: "upstream",
				retryAfterSeconds: 30,
			});
			expect(await retrieve()).toMatchObject({ code: "rate_limited", retryAfterSeconds: 30 });
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});
	});

	describe("a refusal with a code this provider knows", () => {
		it("is remembered for the marker's interval: a configuration fault is the marker's class of problem, and the code is repeated meanwhile", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(
				Object.assign(new Error("x"), { error: "invalid_client", status: 401 }),
			);
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "upstream_rejected",
				reason: "invalid_client",
				retryAfterSeconds: 300,
			});
			expect(await stamp()).toMatchObject({ kind: "rejected", upstreamCode: "invalid_client" });
			setNow(new Date(now().getTime() + 4 * MIN));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "upstream_rejected",
				reason: "invalid_client",
				retryAfterSeconds: 60,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
			setNow(new Date(now().getTime() + MIN));
			await retrieve();
			expect(h.refresh).toHaveBeenCalledTimes(2);
		});

		it.each(["server_error", "temporarily_unavailable"])(
			"is not what the outage codes of RFC 6749 are — %s is an outage whatever status it came with, and is retried promptly",
			async (code) => {
				await h.seed();
				setNow(GONE);
				h.refresh.mockRejectedValue(Object.assign(new Error("x"), { error: code, status: 400 }));
				expect(await retrieve()).toMatchObject({ code: "upstream_rejected", reason: code });
				expect(await stamp()).toMatchObject({ kind: "unavailable", count: 1 });
				await retrieve();
				expect(h.refresh).toHaveBeenCalledTimes(2);
			},
		);

		it("is not what an error nobody can read is: that one may have been processed, and is retried promptly like an outage", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(Object.assign(new Error("x"), { code: "ECONNRESET" }));
			expect(await retrieve()).toMatchObject({ code: "upstream_rejected", reason: "unknown" });
			expect(await stamp()).toMatchObject({ kind: "unavailable", count: 1 });
		});
	});

	describe("what else the stamp does, and does not do", () => {
		it("gives way to the marker: an ineligible answer is the more specific fault", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValueOnce(outage()).mockRejectedValueOnce(outage());
			await retrieve();
			await retrieve();
			setNow(new Date(now().getTime() + limits.refreshFailureBackoffMs));
			h.refresh.mockResolvedValueOnce({ refreshToken: "rt-x" } as never);
			expect(await retrieve()).toMatchObject({
				code: "upstream_token_ineligible",
				reason: "malformed_token_response",
			});
			// The write that left the marker forgot the stamp.
			expect(await stamp()).toBeUndefined();
		});

		it("is written after a refresh whose answer could not be persisted, with what is left of the persist budget: never past the lease", async () => {
			// The write is refused at once, thirty times: the budget's count runs out
			// with time to spare, and the stamp gets what is left.
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("1", now()));
			vi.spyOn(h.store, "replaceCredentials").mockRejectedValue(new Error("redis down"));
			const frozen = now();
			h.deps.now = () => frozen;
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 100);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
			expect(await stamp()).toMatchObject({ kind: "unavailable", count: 1 });
		});

		it("is not written after a persist failure that spent the whole budget: a stamp past the lease could land under the next holder", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("1", now()));
			vi.spyOn(h.store, "replaceCredentials").mockImplementation(
				() => new Promise((_, reject) => setTimeout(() => reject(new Error("redis down")), 200)),
			);
			const noted = vi.spyOn(h.store, "noteRefreshFailure");
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 500);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
			expect(noted).not.toHaveBeenCalled();
		});

		it("gives way to the marker where both stand: the marker is the more specific fault", async () => {
			const grant = await h.seed();
			setNow(GONE);
			const marked = await h.store.replaceCredentials({
				grantId: "g-1",
				expectedVersion: grant.version,
				credentials: { refreshToken: SECRET },
				ineligible: { reason: "scope_exceeded", at: now(), judgedAgainst: 3600 },
				now: now(),
			});
			if (!marked.ok) throw new Error("fixture: the marker was not written");
			await h.store.noteRefreshFailure({
				grantId: "g-1",
				expectedVersion: marked.grant.version,
				failure: { at: now(), kind: "rejected", upstreamCode: "invalid_client" },
				rowMs: limits.ineligibleRetryAfterMs,
				now: now(),
			});
			expect(await retrieve()).toMatchObject({
				code: "upstream_token_ineligible",
				reason: "scope_exceeded",
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it.each([
			["a stamp", "refreshFailure"],
			["a marker", "ineligible"],
		] as const)(
			"does not believe %s dated a day ahead: it would stand until its date caught up",
			async (_, field) => {
				const grant = await h.seed();
				setNow(GONE);
				const ahead = new Date(now().getTime() + 24 * HOUR);
				if (field === "ineligible") {
					await h.store.replaceCredentials({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: { refreshToken: SECRET },
						ineligible: { reason: "scope_exceeded", at: ahead, judgedAgainst: 3600 },
						now: now(),
					});
				} else {
					await h.store.noteRefreshFailure({
						grantId: "g-1",
						expectedVersion: grant.version,
						failure: { at: ahead, kind: "rejected", upstreamCode: "invalid_client" },
						rowMs: limits.ineligibleRetryAfterMs,
						now: now(),
					});
				}
				h.refresh.mockResolvedValue(refreshed("1", now()));
				expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1" });
			},
		);

		it.each([
			["an outage", outage(), { code: "temporarily_unavailable", reason: "upstream" }],
			[
				"a rate limit with advice beyond the ceiling",
				Object.assign(new Error("x"), {
					status: 429,
					response: new Response(null, { status: 429, headers: { "retry-after": "3600" } }),
				}),
				{ code: "rate_limited", reason: "upstream", retryAfterSeconds: 300 },
			],
			[
				"a rate limit with advice below the backoff",
				Object.assign(new Error("x"), {
					status: 429,
					response: new Response(null, { status: 429, headers: { "retry-after": "17" } }),
				}),
				// The same arithmetic as the stamp's: never less than the backoff.
				{ code: "rate_limited", reason: "upstream", retryAfterSeconds: 30 },
			],
			[
				"a refusal with a code this provider knows",
				Object.assign(new Error("x"), { error: "invalid_client", status: 401 }),
				{ code: "upstream_rejected", reason: "invalid_client", retryAfterSeconds: 300 },
			],
		])(
			"answers the failure itself when the stamp could not be written, with the wait the stamp would have said — %s",
			async (_, error, denial) => {
				await h.seed();
				setNow(GONE);
				h.refresh.mockRejectedValue(error);
				vi.spyOn(h.store, "noteRefreshFailure").mockRejectedValue(new Error("redis down"));
				expect(await retrieve()).toStrictEqual({ ok: false, ...denial });
			},
		);

		it("tells the failing caller the row's wait even when its own stamp could not be written: the second outage is told the backoff", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(outage());
			await retrieve();
			expect(await stamp()).toMatchObject({ count: 1 });
			vi.spyOn(h.store, "noteRefreshFailure").mockRejectedValueOnce(new Error("redis down"));
			expect(await retrieve({ correlationId: "req-2" })).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "upstream",
				retryAfterSeconds: 30,
			});
		});

		it("does not wait for a stamp that hangs past the persist budget, and tells the logger", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(outage());
			vi.spyOn(h.store, "noteRefreshFailure").mockReturnValue(new Promise(() => {}));
			const reported: string[] = [];
			h.deps.report = (failure) => reported.push(failure.during);
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 50);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
			expect(reported).toEqual(["upstream", "mark"]);
		});

		it("does not let a stamp that outlived its budget replace a newer one: the store never moves back", async () => {
			// The first call's outage stamp hangs past the persist budget; the lock is
			// let go of; a second call's rate limit is stamped; then the first stamp
			// lands. The rate limit's wait must be what stands.
			await h.seed();
			setNow(GONE);
			const real = h.store.noteRefreshFailure.bind(h.store);
			vi.spyOn(h.store, "noteRefreshFailure").mockImplementationOnce(async (input) => {
				await new Promise((resolve) => setTimeout(resolve, limits.persistRetryBudgetMs + 2_000));
				return real(input);
			});
			h.refresh.mockRejectedValueOnce(outage());
			const first = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 100);
			expect(await first).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });

			setNow(new Date(now().getTime() + 1_000));
			h.refresh.mockRejectedValueOnce(
				Object.assign(new Error("x"), {
					status: 429,
					response: new Response(null, { status: 429, headers: { "retry-after": "120" } }),
				}),
			);
			expect(await retrieve({ correlationId: "req-2" })).toMatchObject({
				code: "rate_limited",
				retryAfterSeconds: 120,
			});
			await vi.advanceTimersByTimeAsync(3_000);
			await Promise.all(h.background);
			expect(await stamp()).toMatchObject({ kind: "rate_limited", retryAfterSeconds: 120 });
			// Three seconds on: the rate limit's wait, and not the outage's.
			expect(await retrieve({ correlationId: "req-3" })).toMatchObject({
				code: "rate_limited",
				retryAfterSeconds: 117,
			});
			expect(h.refresh).toHaveBeenCalledTimes(2);
		});

		it("changes no answer when it cannot be written, and tells the logger", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(outage());
			vi.spyOn(h.store, "noteRefreshFailure").mockRejectedValue(new Error("redis down"));
			const reported: string[] = [];
			h.deps.report = (failure) => reported.push(failure.during);
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "upstream",
			});
			expect(reported).toEqual(["upstream", "mark"]);
			expect(await stamp()).toBeUndefined();
		});

		it("is not written on a grant that was renewed while the upstream was being asked: it says nothing about the new credentials", async () => {
			await h.seed();
			setNow(GONE);
			await h.store.nameIntent({
				grantId: "g-1",
				intent: { handle: "h-re", expiresAt: new Date(now().getTime() + 10 * MIN) },
				now: now(),
			});
			let reject!: (error: unknown) => void;
			h.refresh.mockReturnValueOnce(
				new Promise((_, rej) => {
					reject = rej;
				}),
			);
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			const renewed = await h.store.requireReauthorization({
				grantId: "g-1",
				expectedVersion: (await h.store.find("g-1", now()))?.version ?? -1,
				now: now(),
			});
			expect(renewed.ok).toBe(true);
			reject(outage());
			expect(await answer).toMatchObject({ code: "reauthorization_required" });
			expect(await stamp()).toBeUndefined();
		});

		it("is not left by a failure that keeps the lock: the lock spaces those", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockReturnValue(new Promise(() => {}));
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.upstreamHardTimeoutMs + 100);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
			await Promise.all(h.background);
			expect(await stamp()).toBeUndefined();
		});
	});

	describe("the limit", () => {
		it("must not exceed the ceiling: the backoff is never longer than the marker's interval", () => {
			expect(() =>
				assertFederationGrantRetrievalLimits({
					...limits,
					refreshFailureBackoffMs: limits.ineligibleRetryAfterMs + 1,
				}),
			).toThrow(RangeError);
			expect(() =>
				assertFederationGrantRetrievalLimits({
					...limits,
					refreshFailureBackoffMs: limits.ineligibleRetryAfterMs,
				}),
			).not.toThrow();
		});

		it("must be a non-negative finite number", () => {
			for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY, "30000" as unknown as number]) {
				expect(() =>
					assertFederationGrantRetrievalLimits({ ...limits, refreshFailureBackoffMs: bad }),
				).toThrow(RangeError);
			}
			expect(() =>
				assertFederationGrantRetrievalLimits({ ...limits, refreshFailureBackoffMs: 0 }),
			).not.toThrow();
		});
	});
});
