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
		const version = opened?.grant.version as number;
		for (let i = 0; i < limit; i++) {
			const taken = await h.store.takeRotation?.({
				grantId: "g-1",
				expectedVersion: version,
				limit,
				windowMs: HOUR,
				now: when,
			});
			expect(taken?.ok).toBe(true);
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
		it.each([
			["the default budget", undefined],
			["a budget of four", 4],
		])(
			"a re-answer of the same token with a fixed end, `min_ttl` an hour, polled every 10 s: at most the limit in the hour — under %s",
			async (_, limit) => {
				if (limit !== undefined) budgetOf(limit);
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
				expect(h.refresh.mock.calls.length).toBeLessThanOrEqual(limit ?? 24);
				expect(h.refresh.mock.calls.length).toBeGreaterThan(0);
			},
		);

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

		it("a token one millisecond effective, requested a millisecond apart: at most the limit in each window", async () => {
			budgetOf(5);
			await h.seed();
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), {
					expiresIn: 3600,
					expiresAt: new Date(now().getTime() + 1),
				}),
			);
			setNow(at(HOUR));
			for (let i = 0; i < 50; i++) {
				await retrieve();
				setNow(new Date(now().getTime() + 1));
			}
			expect(h.refresh).toHaveBeenCalledTimes(5);

			// The next window: as many again, and no more.
			setNow(at(2 * HOUR));
			for (let i = 0; i < 50; i++) {
				await retrieve();
				setNow(new Date(now().getTime() + 1));
			}
			expect(h.refresh).toHaveBeenCalledTimes(10);
		});

		it("keeps today's behaviour beside a store that keeps no budget", async () => {
			const { takeRotation: _none, ...withoutBudget } = h.store;
			h.deps.store = withoutBudget;
			budgetOf(2);
			await h.seed();
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

		it("keeps the held token while it is good and serves the request, storing only the rotated refresh token", async () => {
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
		});

		it("asks again no more often than the budget allows while the held token runs down", async () => {
			budgetOf(3);
			await seedBroad();
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), { scope: SCOPES.join(" ") }),
			);
			for (let left = limits.refreshBufferMs; left > 0; left -= 5_000) {
				setNow(at(HOUR - left));
				expect(await retrieve({ scope: ["calendar.write"] })).toMatchObject({
					ok: true,
					accessToken: "at-0",
				});
			}
			expect(h.refresh).toHaveBeenCalledTimes(3);
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
