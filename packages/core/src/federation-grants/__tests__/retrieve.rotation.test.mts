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
import { retrieveFederationGrantToken } from "#/federation-grants/retrieve.mjs";
import type { DelegatedTokens } from "#/federations/types.mjs";
import {
	at,
	connection,
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

/**
 * Every refresh rotates the refresh token at an IdP that rotates, and each
 * rotation is a chance to lose the grant's only credential. These tests pin
 * WHEN a stored token is refreshed and when it is answered as it is — and that
 * a refresh which brought nothing usable costs the grant nothing it had.
 */
describe("retrieveFederationGrantToken — when a token is refreshed, and what a refresh may cost (#593, D5, D10)", () => {
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

	const anHourEachTime = () =>
		h.refresh.mockImplementation(async () => refreshed(`n${h.refresh.mock.calls.length}`, now()));

	describe("a caller that wants more than the stored token has", () => {
		it("is not given a refresh before the token is half spent: there is little more life to be had", async () => {
			await h.seed();
			anHourEachTime();

			setNow(at(30 * MIN - 1));
			expect(await retrieve({ minTtlSeconds: 3600 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
				// Its true lifetime, short of what was asked: the caller decides (D10).
				expiresIn: 1800,
				refreshed: false,
			});
			expect(h.refresh).not.toHaveBeenCalled();

			setNow(at(30 * MIN));
			expect(await retrieve({ minTtlSeconds: 3600 })).toMatchObject({
				accessToken: "at-n1",
				refreshed: true,
			});
		});

		it("refreshes a token whose remaining life only EQUALS what was asked: it has to exceed it", async () => {
			await h.seed();
			anHourEachTime();
			setNow(at(30 * MIN));
			expect(await retrieve({ minTtlSeconds: 1800 })).toMatchObject({ accessToken: "at-n1" });
		});

		it.each([
			["the default refresh buffer", limits.refreshBufferMs],
			["a buffer of zero, which is a setting and not a way round", 0],
		])(
			"costs two rotations an hour at the most, asking an hour of tokens issued for an hour on every poll — under %s",
			async (_, refreshBufferMs) => {
				// No token ever has MORE than its whole life left, so a rule that
				// refreshed whenever `min_ttl` was not met would rotate on every poll.
				await h.seed();
				h.deps.limits = { ...limits, refreshBufferMs };
				anHourEachTime();
				for (let elapsed = 0; elapsed <= HOUR; elapsed += 31_000) {
					setNow(at(elapsed));
					expect((await retrieve({ minTtlSeconds: 3600 })).ok).toBe(true);
				}
				expect(h.refresh.mock.calls.length).toBeLessThanOrEqual(2);
			},
		);

		it("costs no more for a scope the upstream never puts in a token", async () => {
			await h.seed();
			anHourEachTime();
			for (let elapsed = 0; elapsed <= HOUR; elapsed += 31_000) {
				setNow(at(elapsed));
				// Consented to, and never granted: a refresh MAY bring it, so it is
				// asked for — but not on every poll.
				expect(await retrieve({ scope: ["calendar.write"] })).toStrictEqual({
					ok: false,
					code: "invalid_scope",
				});
			}
			expect(h.refresh.mock.calls.length).toBeLessThanOrEqual(2);
		});

		it("is still given a token that has run down to the buffer, whatever it asked", async () => {
			await h.seed();
			anHourEachTime();
			setNow(at(HOUR - limits.refreshBufferMs));
			expect(await retrieve()).toMatchObject({ accessToken: "at-n1", refreshed: true });
		});

		it("answers its own refresh as it is, however long the write took: a call refreshes once", async () => {
			// Four-second tokens, and a write that takes two and a half: by the last
			// look the token is past half its life and inside the buffer. It is this
			// call's own all the same, and is answered with what it has left.
			await h.seed();
			setNow(at(HOUR - 15_000));
			h.refresh.mockImplementation(async () =>
				refreshed("1", now(), { expiresIn: 4, expiresAt: new Date(now().getTime() + 4_000) }),
			);
			const write = h.store.replaceCredentials.bind(h.store);
			vi.spyOn(h.store, "replaceCredentials").mockImplementation(async (input) => {
				await new Promise((resolve) => setTimeout(resolve, 2_500));
				return write(input);
			});
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(2_500);
			expect(await answer).toMatchObject({
				ok: true,
				accessToken: "at-1",
				expiresIn: 1,
				refreshed: true,
			});
		});
	});

	describe("a stored token that is dated in the future", () => {
		const seedDated = (obtainedAt: Date) =>
			h.seed({
				credentials: {
					refreshToken: SECRET,
					accessToken: {
						value: "at-dated",
						tokenType: "Bearer",
						obtainedAt,
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
			});

		it("is not disclosed: it would stay unspent, and alive, for as long as the date is ahead", async () => {
			// Two days ahead. Read naively it has two days and an hour left, under a
			// maximum of one hour.
			await seedDated(at(48 * HOUR));
			anHourEachTime();
			expect(await retrieve()).toMatchObject({ accessToken: "at-n1", refreshed: true });
		});

		it("is disclosed when it is ahead by no more than the refresh buffer absorbs, and never for longer than it was issued for", async () => {
			// Replica A, three seconds ahead, refreshed; replica B looks a moment
			// later. Believing the date costs at most that the token is refreshed
			// so much later — which the buffer is there to absorb. Not believing it
			// costs a second rotation on the heels of the first.
			await seedDated(at(3_000));
			expect(await retrieve()).toMatchObject({ accessToken: "at-dated", refreshed: false });

			h = harness();
			setNow(T0);
			await seedDated(at(limits.refreshBufferMs));
			expect(await retrieve()).toMatchObject({
				accessToken: "at-dated",
				expiresIn: 3600,
				refreshed: false,
			});
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("is not, one millisecond further ahead than that", async () => {
			await seedDated(at(limits.refreshBufferMs + 1));
			anHourEachTime();
			expect(await retrieve()).toMatchObject({ accessToken: "at-n1" });
		});

		it("is allowed what replicas' clocks may differ by, where the buffer is set to less", async () => {
			h.deps.limits = { ...limits, refreshBufferMs: 0 };
			await seedDated(at(limits.revocationSkewMs));
			expect(await retrieve()).toMatchObject({ accessToken: "at-dated", refreshed: false });

			h = harness();
			setNow(T0);
			h.deps.limits = { ...limits, refreshBufferMs: 0 };
			await seedDated(at(limits.revocationSkewMs + 1));
			anHourEachTime();
			expect(await retrieve()).toMatchObject({ accessToken: "at-n1" });
		});

		it("is not carried over by a refresh that brought nothing usable: what is not believed is not kept", async () => {
			await seedDated(at(HOUR));
			h.refresh.mockResolvedValue({
				...refreshed("rotated", now()),
				accessToken: undefined,
			} as DelegatedTokens);
			expect(await retrieve()).toMatchObject({ ok: false, code: "upstream_token_ineligible" });
			expect(await stored()).toStrictEqual({
				refreshToken: `${SECRET}-rotated`,
				accessToken: undefined,
			});
		});
	});

	describe("a refresh that brought nothing usable", () => {
		const garbage = (tag: string): DelegatedTokens =>
			({ ...refreshed(tag, now()), accessToken: undefined }) as DelegatedTokens;

		it("does not cost the grant the healthy token it had", async () => {
			// Forty minutes in, a scope the token lacks is asked for: a refresh, and
			// the adapter answers nonsense. The stored token has twenty minutes left.
			await h.seed();
			setNow(at(40 * MIN));
			h.refresh.mockResolvedValue(garbage("rotated"));

			expect(await retrieve({ scope: ["calendar.write"] })).toStrictEqual({
				ok: false,
				code: "upstream_token_ineligible",
				reason: "malformed_token_response",
				retryAfterSeconds: 300,
			});
			// The rotated refresh token is kept (D5) — and so is what still worked.
			expect(await stored()).toMatchObject({
				refreshToken: `${SECRET}-rotated`,
				accessToken: { value: "at-0", obtainedAt: T0 },
			});

			// A plain request goes on being answered, under the marker, with no
			// upstream call: the marker limits how often the upstream is asked, and
			// is not a reason to withhold a token that is good.
			expect(await retrieve()).toMatchObject({
				ok: true,
				accessToken: "at-0",
				expiresIn: 1200,
				refreshed: false,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});

		it("does not cost it that token when the new one is merely ineligible, either", async () => {
			await h.seed();
			setNow(at(40 * MIN));
			h.refresh.mockResolvedValue(
				refreshed("rotated", now(), {
					expiresIn: 7200,
					expiresAt: new Date(now().getTime() + 2 * HOUR),
				}),
			);
			expect(await retrieve({ minTtlSeconds: 3000 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
				expiresIn: 1200,
				// The upstream was asked, and this is not what it answered.
				refreshed: false,
			});
			expect((await stored())?.refreshToken).toBe(`${SECRET}-rotated`);

			// The same request a minute later: half spent, wanting more, and the
			// marker not due. Answered with the life it has, on a first look too.
			setNow(at(41 * MIN));
			expect(await retrieve({ minTtlSeconds: 3000 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
				refreshed: false,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
			expect((await h.store.find("g-1", now()))?.ineligible?.reason).toBe("lifetime_over_maximum");
		});

		it("answers the marker once that token has run out, and asks the upstream again only when the interval has passed", async () => {
			await h.seed();
			setNow(at(HOUR - 15_000));
			h.refresh.mockResolvedValueOnce(garbage("rotated"));
			// Fifteen seconds of a good token beat a denial: its true lifetime is
			// what the caller is told.
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-0", expiresIn: 15 });

			setNow(at(HOUR));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "upstream_token_ineligible",
				reason: "malformed_token_response",
				retryAfterSeconds: 285,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);

			setNow(at(HOUR - 15_000 + limits.ineligibleRetryAfterMs));
			h.refresh.mockResolvedValueOnce(refreshed("2", now()));
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-2", refreshed: true });
		});

		it("answers the wait that ran out, and not the marker, while somebody else is making the retry", async () => {
			// The marker says "operator", and carries no hint once its interval has
			// passed. What this caller ran into is a refresh in flight that may well
			// recover the grant: it is told to come back, not to give up.
			await h.seed();
			setNow(at(HOUR));
			h.refresh.mockResolvedValueOnce(garbage("rotated"));
			await retrieve();
			setNow(at(HOUR + limits.ineligibleRetryAfterMs));
			h.refresh.mockReturnValueOnce(new Promise(() => {}));

			const holder = retrieve();
			await vi.advanceTimersByTimeAsync(50);
			const waiter = retrieve({ correlationId: "req-2" });
			await vi.advanceTimersByTimeAsync(limits.lockWaitMs + 100);
			expect(await waiter).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "lock_timeout",
			});
			await vi.advanceTimersByTimeAsync(limits.upstreamHardTimeoutMs);
			await holder;
		});

		it("keeps what the look UNDER the lock found, not what the first look found", async () => {
			const grant = await h.seed();
			setNow(at(40 * MIN));
			const theirs = await h.store.acquireRefreshLock("g-1", { ttlMs: 60_000, waitForMs: 0 });
			if (!theirs.acquired) throw new Error("fixture: the lock was not free");
			h.refresh.mockResolvedValue(garbage("rotated"));
			const answer = retrieve({ minTtlSeconds: 3500 });
			await vi.advanceTimersByTimeAsync(1_000);
			// The holder stores a token of its own — half spent already, so that
			// this call still refreshes once it has the lock.
			const moment = now();
			await h.store.replaceCredentials({
				grantId: "g-1",
				expectedVersion: grant.version,
				credentials: {
					refreshToken: `${SECRET}-theirs`,
					accessToken: {
						value: "at-theirs",
						tokenType: "Bearer",
						obtainedAt: new Date(moment.getTime() - 50 * MIN),
						issuedLifetime: 3600,
						scopes: [...SCOPES],
					},
				},
				ineligible: null,
				now: moment,
			});
			await theirs.release();
			await vi.advanceTimersByTimeAsync(1_000);
			await answer;
			// A token from before the wait would be one that was replaced: writing
			// it back would undo somebody else's refresh.
			expect((await stored())?.accessToken?.value).toBe("at-theirs");
		});

		it("never carries over a token the current maximum refuses", async () => {
			await h.seed();
			h.world.connections.set(connection.name, { ...connection, maxAccessTokenLifetime: 1800 });
			setNow(at(10 * MIN));
			h.refresh.mockResolvedValue(garbage("rotated"));
			expect(await retrieve()).toMatchObject({ ok: false, code: "upstream_token_ineligible" });
			expect(await stored()).toStrictEqual({
				refreshToken: `${SECRET}-rotated`,
				accessToken: undefined,
			});
		});

		it("never carries over a token that has died", async () => {
			await h.seed();
			setNow(at(HOUR));
			h.refresh.mockResolvedValue(garbage("rotated"));
			expect(await retrieve()).toMatchObject({ ok: false, code: "upstream_token_ineligible" });
			expect(await stored()).toStrictEqual({
				refreshToken: `${SECRET}-rotated`,
				accessToken: undefined,
			});
		});
	});

	describe("an upstream failure that arrived", () => {
		it.each([
			[
				"a 502 from whatever stands in front of the IdP",
				{ status: 502 },
				"temporarily_unavailable",
			],
			["a connection that timed out", { code: "ETIMEDOUT" }, "temporarily_unavailable"],
			["a connection that was reset", { code: "ECONNRESET" }, "upstream_rejected"],
			[
				"an answer that could not be parsed",
				{ name: "OperationProcessingError" },
				"upstream_rejected",
			],
		])(
			"leaves nothing in flight — %s: the lock is let go of, and the next poll asks again at once (a refusal is remembered instead, D12)",
			async (_, carried, code) => {
				// If the IdP rotated before its answer was lost, the old refresh token
				// is presented again whenever the next refresh comes: waiting out the
				// lock would not change that, and an IdP with a grace window for
				// exactly this takes a prompt retry, not a late one. Keeping the lock
				// is for what is still in flight (D12).
				await h.seed();
				setNow(at(HOUR));
				h.refresh.mockRejectedValueOnce(
					Object.assign(new Error("fetch failed"), { cause: carried, ...carried }),
				);
				expect(await retrieve()).toMatchObject({ ok: false, code });
				await Promise.all(h.background);

				h.refresh.mockResolvedValueOnce(refreshed("recovered", now()));
				expect(await retrieve({ correlationId: "req-2" })).toMatchObject({
					ok: true,
					accessToken: "at-recovered",
				});
				expect(h.refresh).toHaveBeenCalledTimes(2);
			},
		);
	});

	describe("a store that does not answer when asked for the lock", () => {
		it("is waited for as long as the lock may be waited for and a little more, and a lock that arrives after that is let go of", async () => {
			await h.seed();
			setNow(at(HOUR));
			h.refresh.mockResolvedValue(refreshed("1", now()));
			const acquire = h.store.acquireRefreshLock.bind(h.store);
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementationOnce(async (id, options) => {
				await new Promise((resolve) => setTimeout(resolve, 20_000));
				return acquire(id, options);
			});
			const reported: string[] = [];
			h.deps.report = (failure) => reported.push(failure.during);

			let answered: unknown;
			void retrieve().then((result) => {
				answered = result;
			});
			await vi.advanceTimersByTimeAsync(limits.lockWaitMs + 2_999);
			expect(answered).toBeUndefined();
			await vi.advanceTimersByTimeAsync(1);
			expect(answered).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(reported).toEqual(["lock"]);
			expect(h.refresh).not.toHaveBeenCalled();

			// The lock arrives twelve seconds later, for nobody: it is not held for
			// its whole TTL against every replica that needs it.
			await vi.advanceTimersByTimeAsync(12_001);
			const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
			expect(lock.acquired).toBe(true);
		});
	});

	describe("a lock that arrives after the wait for it was given up", () => {
		it("is let go of within bounds, and a release that fails is reported like any other", async () => {
			await h.seed();
			setNow(at(HOUR));
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementationOnce(async () => {
				await new Promise((resolve) => setTimeout(resolve, 20_000));
				return {
					acquired: true,
					waitedMs: 0,
					release: async () => {
						throw new Error("the store lost the connection");
					},
				};
			});
			const reported: string[] = [];
			h.deps.report = (failure) => reported.push(failure.during);
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.lockWaitMs + 3_000);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
			await vi.advanceTimersByTimeAsync(20_000);
			await Promise.all(h.background);
			expect(reported).toEqual(["lock", "release"]);
			expect(vi.getTimerCount()).toBe(0);
		});
	});

	describe("a write that throws", () => {
		it("is tried again after a pause, not in a loop that spends the budget at once", async () => {
			await h.seed();
			setNow(at(HOUR));
			h.refresh.mockResolvedValue(refreshed("1", now()));
			const write = vi
				.spyOn(h.store, "replaceCredentials")
				.mockRejectedValue(new Error("redis down"));
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(50);
			expect(write).toHaveBeenCalledTimes(1);
			await vi.advanceTimersByTimeAsync(100);
			expect(write).toHaveBeenCalledTimes(2);
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		});
	});
});
