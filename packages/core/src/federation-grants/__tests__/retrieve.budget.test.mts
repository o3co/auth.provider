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
	type FederationGrantRetrievalFailure,
	retrieveFederationGrantToken,
} from "#/federation-grants/retrieve.mjs";
import type { FederationGrantStore } from "#/federation-grants/store.mjs";
import type { FederationGrantTokenResult } from "#/federation-grants/types.mjs";
import {
	at,
	CONSENTED,
	type Harness,
	HOUR,
	harness,
	limits,
	MIN,
	now,
	refreshed,
	request,
	SCOPES,
	SECRET,
	setNow,
	T0,
} from "./retrieve.harness.mjs";

const failureOf = (
	result: FederationGrantTokenResult,
): FederationGrantRetrievalFailure | undefined =>
	result.ok || result.code !== "temporarily_unavailable" ? undefined : result.failure;

/**
 * The rotation budget bounds how many upstream refresh-token rotations a grant
 * takes in a window, whatever the upstream answers and whatever a client asks.
 * Half-spent only says when a refresh is worth asking for.
 */
describe("retrieveFederationGrantToken — the rotation budget", () => {
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

	const stored = async () => {
		const opened = await h.store.open("g-1", now());
		return opened?.credentials.state === "ok" ? opened.credentials.value : undefined;
	};

	/** A budget of `limit` rotations an hour. */
	const budgetOf = (limit: number) => {
		h.deps.limits = { ...limits, rotationBudget: limit, rotationWindowMs: HOUR };
	};

	/** Spends the whole budget at `when`, as other calls would have. */
	const spend = async (limit: number, when = now()) => {
		const opened = await h.store.open("g-1", when);
		let version = opened?.grant.version as number;
		for (let i = 0; i < limit; i++) {
			const taken = await h.store.takeRotation?.({
				grantId: "g-1",
				expectedVersion: version,
				limit,
				windowMs: HOUR,
				now: when,
			});
			if (!taken?.ok) throw new Error("fixture: the take was refused");
			version = taken.grant.version;
		}
	};

	type Take = NonNullable<FederationGrantStore["takeRotation"]>;
	/** The memory store's own take. */
	const realTake: Take = (input) => (h.store.takeRotation as Take)(input);
	/** The store, with `take` in place of its own. */
	const withTake = (take: Take) => {
		h.deps.store = { ...h.store, takeRotation: take };
	};

	/** Seeds a grant whose stored token ended at `endsAt` after T0. */
	const seedEndingAt = (endsAt: number) =>
		h.seed({
			credentials: {
				refreshToken: SECRET,
				accessToken: {
					value: "at-0",
					tokenType: "Bearer",
					obtainedAt: T0,
					issuedLifetime: 3600,
					effectiveExpiresAt: at(endsAt),
					scopes: [...SCOPES],
				},
			},
		});

	describe("bounds what an upstream and a client can cause together", () => {
		it("a re-answer of the same token with a fixed end, `min_ttl` an hour, polled every 10 s: the limit in the hour, and no more", async () => {
			budgetOf(4);
			const END = T0.getTime() + HOUR;
			await h.seed();
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), {
					accessToken: "at-0",
					expiresIn: Math.max(1, Math.floor((END - now().getTime()) / 1000)),
					expiresAt: new Date(END),
				}),
			);
			for (let elapsed = 0; elapsed < HOUR; elapsed += 10_000) {
				setNow(at(elapsed));
				// A good token is answered with the life it has, below `min_ttl` too.
				expect(await retrieve({ minTtlSeconds: 3600 })).toMatchObject({
					ok: true,
					accessToken: "at-0",
				});
			}
			expect(h.refresh).toHaveBeenCalledTimes(4);
		});

		it("a token stored already past half its life, five seconds effective of an hour issued, three to answer: at most the limit, and a 429 once nothing stored serves", async () => {
			budgetOf(3);
			await h.seed();
			h.refresh.mockImplementation(async () => {
				const calledAt = now();
				setNow(new Date(calledAt.getTime() + 3_000));
				return refreshed(`n${h.refresh.mock.calls.length}`, calledAt, {
					expiresIn: 3600,
					expiresAt: new Date(calledAt.getTime() + 5_000),
				});
			});
			// Run down to the refresh buffer.
			setNow(at(HOUR - limits.refreshBufferMs));
			const answers: FederationGrantTokenResult[] = [];
			for (let i = 0; i < 10; i++) {
				answers.push(await retrieve());
				setNow(new Date(now().getTime() + 1_000));
			}
			expect(h.refresh).toHaveBeenCalledTimes(3);
			// Every answer is a token that still has life, or the budget's 429.
			for (const answer of answers) {
				if (answer.ok) continue;
				expect(answer).toMatchObject({ code: "rate_limited", reason: "provider" });
			}
			expect(answers.at(-1)).toMatchObject({ ok: false, code: "rate_limited", reason: "provider" });
		});

		it.each([
			["the default budget", undefined],
			["a budget of five", 5],
		])(
			"a token one millisecond effective, requested a millisecond apart: the limit in each window, and no more — under %s",
			async (_, given) => {
				if (given !== undefined) budgetOf(given);
				const limit = given ?? 24;
				await h.seed();
				h.refresh.mockImplementation(async () =>
					refreshed(`n${h.refresh.mock.calls.length}`, now(), {
						expiresIn: 3600,
						expiresAt: new Date(now().getTime() + 1),
					}),
				);
				setNow(at(HOUR));
				for (let i = 0; i < 60; i++) {
					await retrieve();
					setNow(new Date(now().getTime() + 1));
				}
				expect(h.refresh).toHaveBeenCalledTimes(limit);

				// The next window: as many again, and no more.
				setNow(at(2 * HOUR));
				for (let i = 0; i < 60; i++) {
					await retrieve();
					setNow(new Date(now().getTime() + 1));
				}
				expect(h.refresh).toHaveBeenCalledTimes(2 * limit);
			},
		);

		it("keeps today's behaviour beside a store that keeps no budget, whatever its record says", async () => {
			budgetOf(2);
			await h.seed();
			// Spent, as a record could read after a rollback to a store without the member.
			await spend(2, at(HOUR));
			const { takeRotation: _none, ...withoutBudget } = h.store;
			h.deps.store = withoutBudget;
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), {
					expiresIn: 3600,
					expiresAt: new Date(now().getTime() + 1),
				}),
			);
			setNow(at(HOUR));
			for (let i = 0; i < 5; i++) {
				await retrieve();
				setNow(new Date(now().getTime() + 1));
			}
			expect(h.refresh).toHaveBeenCalledTimes(5);
		});
	});

	describe("a spent budget", () => {
		it("answers a good stored token with the life it has, below `min_ttl`, with no lock and no upstream call", async () => {
			budgetOf(2);
			await h.seed();
			await spend(2);
			const lock = vi.spyOn(h.store, "acquireRefreshLock");
			setNow(at(40 * MIN));
			expect(await retrieve({ minTtlSeconds: 3600 })).toStrictEqual({
				ok: true,
				accessToken: "at-0",
				tokenType: "Bearer",
				expiresIn: 20 * 60,
				scopes: [...SCOPES],
				refreshed: false,
			});
			expect(lock).not.toHaveBeenCalled();
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("answers `invalid_scope` for a good token that lacks an asked-for scope", async () => {
			budgetOf(2);
			await h.seed();
			await spend(2);
			setNow(at(40 * MIN));
			expect(await retrieve({ scope: ["calendar.write"] })).toStrictEqual({
				ok: false,
				code: "invalid_scope",
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("answers a 429 with the wait until the window closes, when nothing stored serves the request", async () => {
			budgetOf(2);
			await seedEndingAt(10 * MIN);
			await spend(2, at(5 * MIN));
			const lock = vi.spyOn(h.store, "acquireRefreshLock");
			setNow(at(20 * MIN));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "rate_limited",
				reason: "provider",
				retryAfterSeconds: 45 * 60,
			});
			expect(lock).not.toHaveBeenCalled();
			expect(h.refresh).not.toHaveBeenCalled();
			await Promise.all(h.background);
			expect(h.events.at(-1)).toMatchObject({
				type: "federation.grant.token.denied",
				outcome: "rate_limited/provider",
			});
		});

		it("is spent no longer than the window", async () => {
			budgetOf(2);
			await seedEndingAt(10 * MIN);
			await spend(2, at(5 * MIN));
			h.refresh.mockImplementation(async () => refreshed("next", now()));
			setNow(at(5 * MIN + HOUR));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-next", refreshed: true });
		});
	});

	describe("what is reported when more than one keeps the upstream from being asked", () => {
		it("the ineligibility marker, before the failure stamp and the budget", async () => {
			budgetOf(1);
			const grant = await seedEndingAt(10 * MIN);
			setNow(at(20 * MIN));
			await h.store.replaceCredentials({
				grantId: "g-1",
				expectedVersion: grant.version,
				credentials: { refreshToken: SECRET, accessToken: undefined },
				ineligible: { reason: "no_finite_lifetime", at: now(), judgedAgainst: 3600 },
				now: now(),
			});
			await h.store.noteRefreshFailure({
				grantId: "g-1",
				expectedVersion: grant.version + 1,
				failure: { at: now(), kind: "rate_limited", retryAfterSeconds: 60 },
				rowMs: limits.ineligibleRetryAfterMs,
				now: now(),
			});
			await spend(1);
			expect(await retrieve()).toMatchObject({ ok: false, code: "upstream_token_ineligible" });
		});

		it("the failure stamp, before the budget", async () => {
			budgetOf(1);
			const grant = await seedEndingAt(10 * MIN);
			setNow(at(20 * MIN));
			await h.store.noteRefreshFailure({
				grantId: "g-1",
				expectedVersion: grant.version,
				failure: { at: now(), kind: "rate_limited", retryAfterSeconds: 60 },
				rowMs: limits.ineligibleRetryAfterMs,
				now: now(),
			});
			await spend(1);
			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "rate_limited",
				reason: "upstream",
			});
		});
	});

	describe("the take, under the lock and before the upstream is asked", () => {
		it("is taken once per rotation, at the version the refresh is guarded by", async () => {
			const grant = await seedEndingAt(10 * MIN);
			const take = vi.fn(realTake);
			withTake(take);
			h.refresh.mockImplementation(async () => refreshed("next", now()));
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-next" });
			expect(take).toHaveBeenCalledTimes(1);
			expect(take.mock.calls[0]?.[0]).toEqual({
				grantId: "g-1",
				expectedVersion: grant.version,
				limit: 24,
				windowMs: HOUR,
				now: now(),
			});
			expect((await h.store.open("g-1", now()))?.grant).toMatchObject({
				rotations: { since: at(20 * MIN), count: 1 },
			});
		});

		it("that throws asks the upstream nothing, and answers `temporarily_unavailable` / `storage`", async () => {
			await seedEndingAt(10 * MIN);
			const down = new Error("store down");
			withTake(async () => {
				throw down;
			});
			setNow(at(20 * MIN));
			const result = await retrieve();
			expect(result).toMatchObject({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(failureOf(result)).toMatchObject({ during: "rotation", error: down });
			expect(h.refresh).not.toHaveBeenCalled();
			// The lock is let go of: the next call can take it at once.
			await Promise.all(h.background);
			const next = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(next.acquired).toBe(true);
		});

		it("that does not answer within the soft deadline asks the upstream nothing, and answers `storage`", async () => {
			await seedEndingAt(10 * MIN);
			withTake(() => new Promise(() => {}));
			setNow(at(20 * MIN));
			const pending = retrieve();
			await vi.advanceTimersByTimeAsync(limits.upstreamTimeoutMs);
			const result = await pending;
			expect(result).toMatchObject({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(failureOf(result)).toMatchObject({ during: "rotation" });
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("that does not answer in time keeps the lock: it may still land and bump the version under the next holder", async () => {
			await seedEndingAt(10 * MIN);
			withTake(() => new Promise(() => {}));
			setNow(at(20 * MIN));
			const pending = retrieve();
			await vi.advanceTimersByTimeAsync(limits.upstreamTimeoutMs);
			expect(await pending).toMatchObject({ ok: false, reason: "storage" });
			await Promise.all(h.background);
			expect(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).toEqual({
				acquired: false,
				reason: "timeout",
			});
		});

		it("that answers, if only after the soft deadline, lets the lock go: nothing of it is left in flight", async () => {
			await seedEndingAt(10 * MIN);
			withTake(async (input) => {
				setNow(new Date(now().getTime() + limits.upstreamTimeoutMs));
				return realTake(input);
			});
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({ ok: false, reason: "storage" });
			await Promise.all(h.background);
			expect(
				(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).acquired,
			).toBe(true);
		});

		it("that answers after the soft deadline has passed asks the upstream nothing either", async () => {
			await seedEndingAt(10 * MIN);
			withTake(async (input) => {
				setNow(new Date(now().getTime() + limits.upstreamTimeoutMs));
				return realTake(input);
			});
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("that is refused reads as a concurrent update where the budget is not spent", async () => {
			await seedEndingAt(10 * MIN);
			withTake(async () => ({ ok: false }));
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "temporarily_unavailable",
				reason: "concurrent_update",
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("that is refused because another call took the last rotation answers the spent budget", async () => {
			budgetOf(1);
			await seedEndingAt(10 * MIN);
			withTake(async (input) => {
				// Another replica's take lands first.
				await realTake(input);
				return realTake(input);
			});
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "rate_limited",
				reason: "provider",
				retryAfterSeconds: 3600,
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("that is refused still answers a good stored token", async () => {
			budgetOf(1);
			await h.seed();
			withTake(async (input) => {
				await realTake(input);
				return realTake(input);
			});
			setNow(at(40 * MIN));
			expect(await retrieve({ minTtlSeconds: 3600 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
				refreshed: false,
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});
	});

	describe("an attempt the upstream definitely did not perform", () => {
		const rotationsOf = async () =>
			((await h.store.find("g-1", now())) as { rotations?: unknown } | null)?.rotations;

		it("gives its rotation back: a sustained outage over a whole window, under the defaults, leaves the budget whole, and the first request after it refreshes", async () => {
			await seedEndingAt(10 * MIN);
			h.refresh.mockRejectedValue(Object.assign(new Error("service unavailable"), { status: 503 }));
			const start = 20 * MIN;
			for (let elapsed = start; elapsed < start + HOUR; elapsed += 10_000) {
				setNow(at(elapsed));
				expect(await retrieve()).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			}
			// More attempts than the whole budget, under the failure backoff.
			expect(h.refresh.mock.calls.length).toBeGreaterThan(24);
			expect(await rotationsOf()).toMatchObject({ count: 0 });

			h.refresh.mockReset();
			h.refresh.mockImplementation(async () => refreshed("back", now()));
			setNow(at(start + HOUR + MIN));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-back", refreshed: true });
		});

		it("gives back a rate limit's and a refusal's too: the upstream answered", async () => {
			await seedEndingAt(10 * MIN);
			setNow(at(20 * MIN));
			h.refresh.mockRejectedValueOnce(
				Object.assign(new Error("slow down"), { status: 429, error: "too_many_requests" }),
			);
			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "rate_limited",
				reason: "upstream",
			});
			expect(await rotationsOf()).toMatchObject({ count: 0 });
		});

		it("gives back a refusal's: the upstream answered `invalid_client`", async () => {
			await seedEndingAt(10 * MIN);
			setNow(at(20 * MIN));
			h.refresh.mockRejectedValueOnce(
				Object.assign(new Error("x"), { error: "invalid_client", status: 401 }),
			);
			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "upstream_rejected",
				reason: "invalid_client",
			});
			expect(await rotationsOf()).toMatchObject({ count: 0 });
		});

		it.each([
			["a gateway that timed out", { status: 504 }],
			["a bad gateway", { status: 502 }],
			["an outage the IdP names in its body", { status: 400, error: "temporarily_unavailable" }],
		])(
			"keeps the rotation spent for %s: the request may have reached the IdP",
			async (_, fields) => {
				await seedEndingAt(10 * MIN);
				setNow(at(20 * MIN));
				h.refresh.mockRejectedValueOnce(Object.assign(new Error("x"), fields));
				expect((await retrieve()).ok).toBe(false);
				expect(await rotationsOf()).toMatchObject({ count: 1 });
			},
		);

		it("asks nothing back when the stamp lost on the version: the race is the grant's news, not the budget's", async () => {
			await seedEndingAt(10 * MIN);
			const refund = vi.fn(async () => ({ ok: true as const, grant: {} as never }));
			h.deps.store = {
				...h.store,
				noteRefreshFailure: async () => ({ ok: false }),
				refundRotation: refund,
			};
			const reported: string[] = [];
			h.deps.report = (failure) => reported.push(failure.during);
			setNow(at(20 * MIN));
			h.refresh.mockRejectedValueOnce(Object.assign(new Error("down"), { status: 503 }));
			expect(await retrieve()).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			expect(refund).not.toHaveBeenCalled();
			expect(reported).not.toContain("rotation");
			expect(await rotationsOf()).toMatchObject({ count: 1 });
		});

		it("keeps the lock when the give-back does not answer in time: it bumps the version, and must not land under the next holder", async () => {
			await seedEndingAt(10 * MIN);
			h.deps.store = { ...h.store, refundRotation: () => new Promise(() => {}) };
			const reported: string[] = [];
			h.deps.report = (failure) => reported.push(failure.during);
			setNow(at(20 * MIN));
			h.refresh.mockRejectedValueOnce(Object.assign(new Error("down"), { status: 503 }));
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs);
			expect(await answer).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			expect(reported).toContain("rotation");
			await Promise.all(h.background);
			expect(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).toEqual({
				acquired: false,
				reason: "timeout",
			});
		});

		it("keeps the rotation spent when the outcome is unknown: a request given up on may have rotated", async () => {
			await seedEndingAt(10 * MIN);
			setNow(at(20 * MIN));
			h.refresh.mockRejectedValueOnce(
				Object.assign(new Error("timed out"), { name: "TimeoutError" }),
			);
			expect(await retrieve()).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			expect(await rotationsOf()).toMatchObject({ count: 1 });
		});

		it.each([
			["refused", async () => ({ ok: false as const })],
			[
				"throws",
				async (): Promise<never> => {
					throw new Error("store down");
				},
			],
		])(
			"keeps it spent when the give-back is %s, reports it, and answers the same",
			async (_, refund) => {
				await seedEndingAt(10 * MIN);
				h.deps.store = { ...h.store, refundRotation: refund };
				const reported: string[] = [];
				h.deps.report = (failure) => reported.push(failure.during);
				setNow(at(20 * MIN));
				h.refresh.mockRejectedValueOnce(Object.assign(new Error("down"), { status: 503 }));
				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "temporarily_unavailable",
					reason: "upstream",
				});
				expect(await rotationsOf()).toMatchObject({ count: 1 });
				expect(reported).toContain("rotation");
				// The lock is let go of: nothing is in flight.
				await Promise.all(h.background);
				expect(
					(await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 })).acquired,
				).toBe(true);
			},
		);
	});

	describe("the version the take left", () => {
		type Refund = NonNullable<FederationGrantStore["refundRotation"]>;
		const realRefund: Refund = (input) => (h.store.refundRotation as Refund)(input);

		/** Spies on every guarded write after the take, and answers the versions each named. */
		const guardedWrites = () => {
			const named: Array<readonly [string, number]> = [];
			const spy =
				<I extends { readonly expectedVersion: number }, R>(name: string, write: (input: I) => R) =>
				(input: I): R => {
					named.push([name, input.expectedVersion]);
					return write(input);
				};
			h.deps.store = {
				...h.store,
				replaceCredentials: spy("replaceCredentials", h.store.replaceCredentials),
				requireReauthorization: spy("requireReauthorization", h.store.requireReauthorization),
				noteRefreshFailure: spy("noteRefreshFailure", h.store.noteRefreshFailure),
				refundRotation: spy("refundRotation", realRefund),
			};
			return named;
		};

		it("guards the refresh's write by it, one past the version the look read", async () => {
			const grant = await seedEndingAt(10 * MIN);
			const named = guardedWrites();
			h.refresh.mockImplementation(async () => refreshed("next", now()));
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-next", refreshed: true });
			expect(named).toEqual([["replaceCredentials", grant.version + 1]]);
		});

		it("guards the failure stamp and the give-back by it", async () => {
			const grant = await seedEndingAt(10 * MIN);
			const named = guardedWrites();
			h.refresh.mockRejectedValueOnce(Object.assign(new Error("down"), { status: 503 }));
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			expect(named).toEqual([
				["noteRefreshFailure", grant.version + 1],
				["refundRotation", grant.version + 1],
			]);
			expect((await h.store.find("g-1", now()))?.version).toBe(grant.version + 2);
		});

		it("guards the mark an `invalid_grant` leaves by it", async () => {
			const grant = await seedEndingAt(10 * MIN);
			const named = guardedWrites();
			h.refresh.mockRejectedValueOnce(
				Object.assign(new Error("x"), { error: "invalid_grant", status: 400 }),
			);
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({
				ok: false,
				code: "reauthorization_required",
				reason: "upstream_invalid_grant",
			});
			expect(named).toEqual([["requireReauthorization", grant.version + 1]]);
		});

		it("is the version the look read for a store whose take does not bump: its writes are guarded by that", async () => {
			const grant = await seedEndingAt(10 * MIN);
			const named = guardedWrites();
			const store = h.deps.store;
			// A take that does not bump, as a store that predates the bump does.
			h.deps.store = {
				...store,
				takeRotation: async (input) => {
					const found = await h.store.find(input.grantId, input.now);
					return found === null ? { ok: false } : { ok: true, grant: found };
				},
			};
			h.refresh.mockImplementation(async () => refreshed("next", now()));
			setNow(at(20 * MIN));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-next", refreshed: true });
			expect(named).toEqual([["replaceCredentials", grant.version]]);
		});

		it.each([
			["a fraction", 2.5],
			["NaN", Number.NaN],
			["a string", "3"],
		])(
			"that is %s asks the upstream nothing, and answers `storage`: no write could be guarded by it",
			async (_, version) => {
				await seedEndingAt(10 * MIN);
				withTake(async (input) => {
					const taken = await realTake(input);
					return taken.ok
						? { ok: true, grant: { ...taken.grant, version: version as number } }
						: taken;
				});
				setNow(at(20 * MIN));
				const result = await retrieve();
				expect(result).toMatchObject({
					ok: false,
					code: "temporarily_unavailable",
					reason: "storage",
				});
				expect(failureOf(result)).toMatchObject({ during: "rotation" });
				expect(h.refresh).not.toHaveBeenCalled();
			},
		);

		it("refuses a give-back that lands after the next holder's take, and the next holder's rotated token is stored and answered", async () => {
			await seedEndingAt(10 * MIN);
			// The first attempt's give-back is held back, and let go of only once the
			// next attempt has taken its rotation and is asking the upstream.
			let letGo!: () => void;
			const held = new Promise<void>((resolve) => {
				letGo = resolve;
			});
			const late: Promise<Awaited<ReturnType<Refund>>>[] = [];
			h.deps.store = {
				...h.store,
				refundRotation: (input) => {
					const landed = held.then(() => realRefund(input));
					late.push(landed);
					return landed;
				},
			};

			setNow(at(20 * MIN));
			h.refresh.mockRejectedValueOnce(Object.assign(new Error("down"), { status: 503 }));
			const first = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs);
			expect(await first).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			await Promise.all(h.background);

			// The first holder's lock has run out, and its failure no longer holds the upstream off.
			setNow(at(30 * MIN));
			let lateOutcome: Awaited<ReturnType<Refund>> | undefined;
			h.refresh.mockImplementationOnce(async () => {
				letGo();
				lateOutcome = await late[0];
				return refreshed("second", now());
			});
			expect(await retrieve()).toMatchObject({
				ok: true,
				accessToken: "at-second",
				refreshed: true,
			});
			expect(lateOutcome).toEqual({ ok: false });
			expect(await stored()).toMatchObject({
				refreshToken: `${SECRET}-second`,
				accessToken: { value: "at-second" },
			});
			// The first attempt's rotation stays spent: an overcount, never a lost write.
			expect((await h.store.find("g-1", now())) as { rotations?: unknown }).toMatchObject({
				rotations: { since: at(20 * MIN), count: 2 },
			});
		});
	});

	describe("a refresh whose answer carries less of what was asked than the token held", () => {
		/** The stored token carries a consented scope beyond the grant's, as a broadening IdP leaves it. */
		const seedBroad = () =>
			h.seed({
				credentials: {
					refreshToken: SECRET,
					accessToken: {
						value: "at-0",
						tokenType: "Bearer",
						obtainedAt: T0,
						issuedLifetime: 3600,
						effectiveExpiresAt: at(HOUR),
						scopes: [...CONSENTED],
					},
				},
			});

		it("keeps the held token while it is good and serves the request, storing only the rotated refresh token and the marker", async () => {
			await seedBroad();
			// The upstream answers the grant's scopes alone.
			h.refresh.mockImplementation(async () =>
				refreshed("narrow", now(), { scope: SCOPES.join(" ") }),
			);
			setNow(at(59 * MIN));
			expect(await retrieve({ scope: ["calendar.write"], minTtlSeconds: 3600 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
				scopes: [...CONSENTED],
				refreshed: false,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
			const held = await stored();
			expect(held?.refreshToken).toBe(`${SECRET}-narrow`);
			expect(held?.accessToken).toMatchObject({ value: "at-0", scopes: [...CONSENTED] });
			// The marker keeps the upstream from being asked again about it at once.
			expect(await h.store.find("g-1", now())).toMatchObject({
				ineligible: { reason: "scope_not_granted", at: at(59 * MIN) },
			});
		});

		it("honours a narrowing of the grant's own scopes: the fresh token is stored and answered", async () => {
			await seedBroad();
			// The user withdrew `calendar.read` upstream: a scope of the grant's own.
			h.refresh.mockImplementation(async () =>
				refreshed("narrowed", now(), { scope: "openid offline_access" }),
			);
			setNow(at(59 * MIN));
			expect(await retrieve({ scope: ["calendar.read"], minTtlSeconds: 3600 })).toStrictEqual({
				ok: false,
				code: "invalid_scope",
			});
			expect((await stored())?.accessToken).toMatchObject({
				value: "at-narrowed",
				scopes: ["openid", "offline_access"],
			});
			expect((await h.store.find("g-1", now()))?.ineligible).toBeUndefined();
			// And a request the narrowed token serves is answered from it.
			expect(await retrieve({ scope: ["openid"] })).toMatchObject({
				ok: true,
				accessToken: "at-narrowed",
			});
		});

		it("asks again at most once per marker interval, not once per request", async () => {
			await seedBroad();
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), { scope: SCOPES.join(" ") }),
			);
			// Half spent from 30 minutes on: every poll wants more than the token has.
			for (let elapsed = 30 * MIN; elapsed < 50 * MIN; elapsed += 10_000) {
				setNow(at(elapsed));
				expect(await retrieve({ scope: ["calendar.write"], minTtlSeconds: 3600 })).toMatchObject({
					ok: true,
					accessToken: "at-0",
				});
			}
			// At 30, 35, 40 and 45 minutes: one per `ineligibleRetryAfter`.
			expect(limits.ineligibleRetryAfterMs).toBe(5 * MIN);
			expect(h.refresh).toHaveBeenCalledTimes(4);
		});

		it("does not keep the marker from a refresh once the held token has died: the next request refreshes", async () => {
			await seedBroad();
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), { scope: SCOPES.join(" ") }),
			);
			setNow(at(HOUR - 20_000));
			expect(await retrieve({ scope: ["calendar.write"] })).toMatchObject({ accessToken: "at-0" });
			// The marker stands, and the held token is gone.
			setNow(at(HOUR + 1_000));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-n2", refreshed: true });
			expect(h.refresh).toHaveBeenCalledTimes(2);
		});

		it("replaces it where the request asked for nothing the new token lacks", async () => {
			await seedBroad();
			h.refresh.mockImplementation(async () =>
				refreshed("narrow", now(), { scope: SCOPES.join(" ") }),
			);
			setNow(at(59 * MIN));
			expect(await retrieve({ scope: ["calendar.read"], minTtlSeconds: 3600 })).toMatchObject({
				ok: true,
				accessToken: "at-narrow",
				refreshed: true,
			});
			expect((await stored())?.accessToken?.value).toBe("at-narrow");
		});

		it("stores the narrower token once the held one has died: nothing better is held", async () => {
			await seedBroad();
			h.refresh.mockImplementation(async () =>
				refreshed("narrow", now(), { scope: SCOPES.join(" ") }),
			);
			setNow(at(HOUR + MIN));
			expect(await retrieve({ scope: ["calendar.write"] })).toStrictEqual({
				ok: false,
				code: "invalid_scope",
			});
			expect((await stored())?.accessToken?.value).toBe("at-narrow");
		});
	});
});
