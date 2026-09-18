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
	type FederationGrantRefreshedToken,
	retrieveFederationGrantToken,
} from "#/federation-grants/retrieve.mjs";
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

/** Fifteen seconds before the seeded token runs out: inside the refresh buffer. */
const DUE = at(HOUR - 15_000);
/** The seeded token has just run out: nothing is left that a refresh could keep. */
const GONE = at(HOUR);

const lockIsFree = async (h: Harness): Promise<boolean> => {
	const lock = await h.store.acquireRefreshLock("g-1", { ttlMs: 1_000, waitForMs: 0 });
	if (lock.acquired) await lock.release();
	return lock.acquired;
};

describe("retrieveFederationGrantToken — dependencies and upstreams that misbehave (#593, D5, D12)", () => {
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

	describe("a lease that is already spent", () => {
		/** The look under the lock takes `ms`: the second boundary read is the slow one. */
		const slowLookUnderLock = (ms: number) => {
			let reads = 0;
			h.deps.grantsBoundary = async () => {
				reads += 1;
				if (reads === 2) await new Promise((resolve) => setTimeout(resolve, ms));
				return null;
			};
		};

		it("does not ask the upstream once the time a caller waits has gone: a rotation nobody waits for is a credential at risk", async () => {
			// With the lock held for 30 s and the look under it taking 12, a refresh
			// started now would run toward a deadline it was given 25 s to meet with
			// 13 left — and with a slower look, none, or none of the lock either, and
			// two replicas would present one refresh token.
			await h.seed();
			setNow(GONE);
			slowLookUnderLock(12_000);
			h.refresh.mockResolvedValue(refreshed("rotated", DUE));

			const reported: Array<{ during: string }> = [];
			h.deps.report = (failure) => reported.push(failure);
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(12_000);
			// `storage`, not `upstream`: the upstream was never asked, and what was
			// slow was the look under the lock.
			expect(await answer).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(reported.map((failure) => failure.during)).toEqual(["refresh"]);
			expect(h.refresh).not.toHaveBeenCalled();
			expect((await stored())?.refreshToken).toBe(SECRET);
			await Promise.all(h.background);
			expect(await lockIsFree(h)).toBe(true);
		});

		it("counts the lease from when the store STARTED the TTL, not from when it acknowledged the lock: an acknowledgement that came late has spent the lease already", async () => {
			// The store took the lock seven seconds before its answer arrived, and
			// the look under the lock takes four more: eleven of the lease are gone,
			// and the caller's ten with them. Counted from the acknowledgement, only
			// four would be, and the upstream would be asked.
			await h.seed();
			setNow(GONE);
			const real = h.store.acquireRefreshLock.bind(h.store);
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementationOnce(async (id, options) => {
				const lock = await real(id, options);
				await new Promise((resolve) => setTimeout(resolve, 7_000));
				return lock;
			});
			slowLookUnderLock(4_000);
			h.refresh.mockResolvedValue(refreshed("rotated", DUE));
			const reported: string[] = [];
			h.deps.report = (failure) => reported.push(failure.during);
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(11_000);
			expect(await answer).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			expect(reported).toEqual(["refresh"]);
			expect(h.refresh).not.toHaveBeenCalled();
			await Promise.all(h.background);
			expect(await lockIsFree(h)).toBe(true);
		});

		it("aborts the upstream at the hard deadline counted from the lease's start", async () => {
			await h.seed();
			setNow(GONE);
			const real = h.store.acquireRefreshLock.bind(h.store);
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementationOnce(async (id, options) => {
				const lock = await real(id, options);
				await new Promise((resolve) => setTimeout(resolve, 5_000));
				return lock;
			});
			let aborted = false;
			h.refresh.mockImplementation(
				({ signal }) =>
					new Promise((_, reject) => {
						signal?.addEventListener("abort", () => {
							aborted = true;
							reject(new Error("aborted"));
						});
					}),
			);
			const answer = retrieve();
			// Five seconds until the lock is acknowledged, then the caller's wait:
			// ten seconds of the lease, five of which were gone.
			await vi.advanceTimersByTimeAsync(10_000);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
			// The hard deadline: twenty-five of the lease, twenty from here.
			await vi.advanceTimersByTimeAsync(14_999);
			expect(aborted).toBe(false);
			await vi.advanceTimersByTimeAsync(1);
			expect(aborted).toBe(true);
			await Promise.all(h.background);
		});

		it("refuses a lease it cannot date — a wait that is not a number, negative, or longer than the whole round trip — and lets go of the lock: a refresh does not run on a lease of unknown length", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("rotated", DUE));
			for (const waitedMs of [Number.NaN, "0" as unknown as number, -1, 1]) {
				const real = h.store.acquireRefreshLock.bind(h.store);
				vi.spyOn(h.store, "acquireRefreshLock").mockImplementationOnce(async (id, options) => {
					const lock = await real(id, options);
					return lock.acquired ? { ...lock, waitedMs } : lock;
				});
				const reported: string[] = [];
				h.deps.report = (failure) => reported.push(failure.during);
				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "temporarily_unavailable",
					reason: "storage",
				});
				expect(reported).toEqual(["lock"]);
				await Promise.all(h.background);
				expect(await lockIsFree(h)).toBe(true);
			}
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("does not ask it after the lock itself has run out, when another replica may be asking", async () => {
			await h.seed();
			setNow(DUE);
			slowLookUnderLock(limits.refreshLockTtlMs + 1_000);
			h.refresh.mockResolvedValue(refreshed("rotated", DUE));

			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.refreshLockTtlMs + 1_000);
			expect(await answer).toMatchObject({ ok: false, code: "temporarily_unavailable" });
			expect(h.refresh).not.toHaveBeenCalled();
		});
	});

	describe("a dependency that throws where it should have rejected", () => {
		it("answers 503 for a boundary reader that throws, as for one that rejects", async () => {
			await h.seed();
			h.deps.grantsBoundary = () => {
				throw new Error("not even a promise");
			};
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
		});

		it("classifies a refresher that throws, as one that rejects", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockImplementation(() => {
				throw Object.assign(new Error("x"), { error: "invalid_grant" });
			});
			expect(await retrieve()).toMatchObject({
				code: "reauthorization_required",
				reason: "upstream_invalid_grant",
			});
			await Promise.all(h.background);
			expect(await lockIsFree(h)).toBe(true);
		});

		it("retries a write that throws synchronously, as one that rejects", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(() => {
				throw new Error("not even a promise");
			});
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(500);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1" });
		});

		it("never leaves the lock behind: not for a refresher lookup that throws, nor for a clock that does", async () => {
			await h.seed();
			setNow(DUE);
			h.deps.refresher = () => {
				throw new Error("composition bug");
			};
			await expect(retrieve()).rejects.toThrow("composition bug");
			expect(await lockIsFree(h)).toBe(true);

			h = harness();
			setNow(T0);
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			let calls = 0;
			h.deps.now = () => {
				calls += 1;
				// Past the first look and the lock: the reading that starts the lease.
				if (calls === 3) throw new Error("clock bug");
				return now();
			};
			await expect(retrieve()).rejects.toThrow("clock bug");
			h.deps.now = () => now();
			expect(await lockIsFree(h)).toBe(true);
		});

		it("still answers, and still lets go of the lock, when the late work cannot be handed over", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			h.deps.background = () => {
				throw new Error("no registry");
			};
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1" });
			await vi.advanceTimersByTimeAsync(10);
			expect(await lockIsFree(h)).toBe(true);
		});
	});

	describe("an upstream answer that is not what an adapter should report", () => {
		const garbage: Array<[string, Partial<Record<keyof FederationGrantRefreshedToken, unknown>>]> =
			[
				["an expiry that is a number", { expiresAt: DUE.getTime() + HOUR }],
				["an expiry that is a string", { expiresAt: "2026-09-18T01:59:45.000Z" }],
				["scopes as an array", { scope: ["openid", "calendar.read"] }],
				["no access token", { accessToken: undefined }],
				["an empty access token", { accessToken: "" }],
				["an access token that is not a string", { accessToken: 42 }],
				["a lifetime that is a string", { expiresIn: "3600" }],
				["a token type that is not a string", { tokenType: 7 }],
			];

		for (const [what, over] of garbage) {
			it(`${what}: the rotated refresh token is kept all the same, nothing is disclosed, and a marker is left`, async () => {
				await h.seed();
				setNow(GONE);
				h.refresh.mockResolvedValue({
					...refreshed("rotated", GONE),
					...over,
				} as FederationGrantRefreshedToken);

				expect(await retrieve()).toStrictEqual({
					ok: false,
					code: "upstream_token_ineligible",
					reason: "malformed_token_response",
					retryAfterSeconds: 300,
				});
				// Discarding the response would discard the only valid credential (D5).
				expect(await stored()).toStrictEqual({ refreshToken: `${SECRET}-rotated` });
				// And the marker keeps a broken adapter from rotating on every request.
				await retrieve();
				expect(h.refresh).toHaveBeenCalledTimes(1);
			});
		}

		it("reads an answer whose fields throw when they are read: malformed, the rotated refresh token kept, and the lock let go of", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue({
				refreshToken: `${SECRET}-rotated`,
				get accessToken(): string {
					throw new Error("a getter that throws");
				},
			} as FederationGrantRefreshedToken);
			expect(await retrieve()).toMatchObject({
				code: "upstream_token_ineligible",
				reason: "malformed_token_response",
			});
			expect(await stored()).toStrictEqual({ refreshToken: `${SECRET}-rotated` });
			await Promise.all(h.background);
			expect(await lockIsFree(h)).toBe(true);

			// Even the refresh token's: then the stored one is what is kept.
			setNow(new Date(now().getTime() + limits.ineligibleRetryAfterMs));
			h.refresh.mockResolvedValue({
				get refreshToken(): string {
					throw new Error("a getter that throws");
				},
			} as FederationGrantRefreshedToken);
			expect(await retrieve()).toMatchObject({ reason: "malformed_token_response" });
			expect(await stored()).toStrictEqual({ refreshToken: `${SECRET}-rotated` });
		});

		it("treats an answer that is not an object at all as malformed, and lets go of the lock", async () => {
			await h.seed();
			setNow(GONE);
			for (const answer of [undefined, null, "at-1", 42]) {
				h.refresh.mockResolvedValueOnce(answer as unknown as FederationGrantRefreshedToken);
				expect(await retrieve()).toMatchObject({
					code: "upstream_token_ineligible",
					reason: "malformed_token_response",
				});
				expect((await stored())?.refreshToken).toBe(SECRET);
				await Promise.all(h.background);
				expect(await lockIsFree(h)).toBe(true);
				setNow(new Date(now().getTime() + limits.ineligibleRetryAfterMs));
			}
		});

		it("keeps the stored refresh token when the new one is not a usable string", async () => {
			await h.seed();
			setNow(DUE);
			for (const refreshToken of ["", 42, null]) {
				h.refresh.mockResolvedValueOnce({
					...refreshed("1", now()),
					refreshToken,
				} as unknown as FederationGrantRefreshedToken);
				expect((await retrieve()).ok).toBe(true);
				expect((await stored())?.refreshToken).toBe(SECRET);
				setNow(new Date(now().getTime() + HOUR));
			}
		});

		it("reads an empty scope as none named — the grant's — and not as a token that carries nothing (RFC 6749 §6)", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE, { scope: "  " }));
			expect(await retrieve({ scope: ["calendar.read"] })).toMatchObject({
				ok: true,
				scopes: [...SCOPES],
			});
		});

		it("dates a token inside the call even when the adapter's expiry is in the past", async () => {
			await h.seed();
			setNow(DUE);
			let resolve!: (value: FederationGrantRefreshedToken) => void;
			h.refresh.mockReturnValueOnce(
				new Promise((res) => {
					resolve = res;
				}),
			);
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(2_000);
			resolve(refreshed("1", DUE, { expiresAt: new Date(0) }));
			expect((await answer).ok).toBe(true);
			// `expiresIn` is what the upstream issued; the wild anchor is held to when
			// the call began, which is the earlier, and so the shorter, reading.
			expect((await stored())?.accessToken?.obtainedAt).toEqual(DUE);
		});
	});

	describe("a client that asks for more than a refresh can give", () => {
		it("does not refresh tokens that are issued with less life than the buffer on every request, nor keep them until they die", async () => {
			// Twenty-second tokens under a thirty-second buffer: each is inside the
			// buffer from the moment it is obtained.
			await h.seed();
			setNow(DUE);
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), {
					expiresIn: 20,
					expiresAt: new Date(now().getTime() + 20_000),
				}),
			);
			expect(await retrieve()).toMatchObject({ accessToken: "at-n1", expiresIn: 20 });
			setNow(new Date(now().getTime() + 9_000));
			expect(await retrieve()).toMatchObject({ accessToken: "at-n1", expiresIn: 11 });
			// Half spent, it is a token like any other: inside the refresh buffer,
			// and refreshed.
			setNow(new Date(now().getTime() + 1_000));
			expect(await retrieve()).toMatchObject({ accessToken: "at-n2", refreshed: true });
		});

		it("applies on the look under the lock too: a waiter does not rotate again right after the holder", async () => {
			await h.seed();
			setNow(at(40 * MIN));
			let resolve!: (value: FederationGrantRefreshedToken) => void;
			h.refresh.mockReturnValueOnce(
				new Promise((res) => {
					resolve = res;
				}),
			);
			const holder = retrieve({ minTtlSeconds: 3600 });
			await vi.advanceTimersByTimeAsync(50);
			const waiter = retrieve({ minTtlSeconds: 3600, correlationId: "req-2" });
			await vi.advanceTimersByTimeAsync(200);
			resolve(refreshed("1", now()));
			await vi.advanceTimersByTimeAsync(200);
			expect(await holder).toMatchObject({ accessToken: "at-1", refreshed: true });
			expect(await waiter).toMatchObject({ accessToken: "at-1", refreshed: false });
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});

		it("never answers a token that is already dead, however it came by it", async () => {
			// Its own, and dead on arrival: two-second tokens from an upstream that
			// took three to answer.
			await h.seed();
			setNow(DUE);
			let resolve!: (value: FederationGrantRefreshedToken) => void;
			h.refresh.mockReturnValueOnce(
				new Promise((res) => {
					resolve = res;
				}),
			);
			const answer = retrieve();
			const asked = now();
			await vi.advanceTimersByTimeAsync(3_000);
			resolve(
				refreshed("1", asked, { expiresIn: 2, expiresAt: new Date(asked.getTime() + 2_000) }),
			);
			// Nothing overtook this call: what failed it is the upstream's token.
			expect(await answer).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "upstream",
			});
		});

		it("is not given one for a scope the upstream never puts in a token, either", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockImplementation(async () =>
				refreshed(`n${h.refresh.mock.calls.length}`, now(), { scope: "openid" }),
			);
			for (let i = 0; i < 4; i++) {
				expect(await retrieve({ scope: ["calendar.read"] })).toStrictEqual({
					ok: false,
					code: "invalid_scope",
				});
				setNow(new Date(now().getTime() + 5_000));
			}
			expect(h.refresh).toHaveBeenCalledTimes(1);
		});
	});

	describe("what is left running", () => {
		it("no timer, once a call has been answered and its late work is done", async () => {
			await h.seed();
			setNow(at(10 * MIN));
			await retrieve();
			// The record of the use and the audit are not waited for by the answer;
			// each is bounded by a timer that is gone once they are done.
			await Promise.all(h.background);
			expect(vi.getTimerCount()).toBe(0);

			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			await retrieve();
			await Promise.all(h.background);
			expect(vi.getTimerCount()).toBe(0);

			// A write that threw once: the pause and the budget are both done with.
			setNow(new Date(DUE.getTime() + HOUR));
			h.refresh.mockResolvedValue(refreshed("2", now()));
			vi.spyOn(h.store, "replaceCredentials").mockRejectedValueOnce(new Error("blip"));
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(500);
			await answer;
			await Promise.all(h.background);
			expect(vi.getTimerCount()).toBe(0);
		});

		it("not the lock, when the audit sink never answers: nothing is audited while the lock is held", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			h.deps.audit = (event) =>
				event.type === "federation.grant.refreshed" ? new Promise(() => {}) : undefined;
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			expect(await lockIsFree(h)).toBe(true);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1" });
		});

		it("not the caller, when letting go of the lock is slow: a refresh that was persisted is not answered as an outage", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const real = h.store.acquireRefreshLock.bind(h.store);
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementation(async (id, options) => {
				const lock = await real(id, options);
				if (!lock.acquired) return lock;
				return {
					...lock,
					release: async () => {
						await new Promise((resolve) => setTimeout(resolve, 20_000));
						await lock.release();
					},
				};
			});
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1", refreshed: true });
			await vi.advanceTimersByTimeAsync(20_000);
			await Promise.all(h.background);
		});

		it("not an endless loop, when the clock it is given does not move", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const write = vi
				.spyOn(h.store, "replaceCredentials")
				.mockRejectedValue(new Error("redis down"));
			const frozen = now();
			h.deps.now = () => frozen;

			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(60_000);
			expect(await answer).toMatchObject({ code: "temporarily_unavailable" });
			expect(write.mock.calls.length).toBeLessThan(100);
		});
	});

	describe("what is reported, and what is waited for", () => {
		it("answers a failure the classifier cannot even read like any other that arrived: a typed answer, and the lock let go of", async () => {
			await h.seed();
			setNow(GONE);
			// `String()` of this throws, and so does the classifier.
			h.refresh.mockRejectedValue(Object.create(null));
			expect(await retrieve()).toStrictEqual({
				ok: false,
				code: "upstream_rejected",
				reason: "unknown",
			});
			await Promise.all(h.background);
			// Audited as the failure it is, and not as a bug in the worker — which
			// would keep the lock, as for something still in flight.
			expect(h.events.map((event) => `${event.type} ${event.outcome}`)).toContain(
				"federation.grant.refresh_failed upstream_rejected/unknown",
			);
			expect(await lockIsFree(h)).toBe(true);
		});

		it("hands over nothing that can never settle: a sink, a store or a lock that does not answer is waited for so long, and no longer", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			h.deps.audit = () => new Promise(() => {});
			vi.spyOn(h.store, "touch").mockReturnValue(new Promise(() => {}));
			const real = h.store.acquireRefreshLock.bind(h.store);
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementation(async (id, options) => {
				const lock = await real(id, options);
				return lock.acquired ? { ...lock, release: () => new Promise(() => {}) } : lock;
			});
			const reported: Array<{ during: string }> = [];
			h.deps.report = (failure) => reported.push(failure);

			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-1" });
			let settled = false;
			void Promise.all(h.background).then(() => {
				settled = true;
			});
			await vi.advanceTimersByTimeAsync(3 * limits.persistRetryBudgetMs + 1_000);
			// A shutdown that drains what was handed over finishes.
			expect(settled).toBe(true);
			expect(reported.map((failure) => failure.during).sort()).toEqual([
				"audit",
				"audit",
				"release",
				"touch",
			]);
			expect(vi.getTimerCount()).toBe(0);
		});

		it("does not wait for a mark that hangs, under the lock", async () => {
			await h.seed();
			setNow(GONE);
			h.refresh.mockRejectedValue(Object.assign(new Error("x"), { error: "invalid_grant" }));
			vi.spyOn(h.store, "requireReauthorization").mockReturnValue(new Promise(() => {}));
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 100);
			expect(await answer).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "storage",
			});
			await Promise.all(h.background);
			expect(await lockIsFree(h)).toBe(true);
		});

		it("does not wait for the lock to be let go of when the look under it found a token to answer", async () => {
			const grant = await h.seed();
			setNow(DUE);
			const real = h.store.acquireRefreshLock.bind(h.store);
			vi.spyOn(h.store, "acquireRefreshLock").mockImplementation(async (id, options) => {
				const lock = await real(id, options);
				if (!lock.acquired) return lock;
				// Somebody else refreshed while this call was getting the lock.
				await h.store.replaceCredentials({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: {
						refreshToken: `${SECRET}-theirs`,
						accessToken: {
							value: "at-theirs",
							tokenType: "Bearer",
							obtainedAt: now(),
							issuedLifetime: 3600,
							scopes: [...SCOPES],
						},
					},
					ineligible: null,
					now: now(),
				});
				return {
					acquired: true,
					waitedMs: 0,
					release: () => new Promise((resolve) => setTimeout(resolve, 20_000)),
				};
			});
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-theirs", refreshed: false });
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("does not tell the audit sink of a backstop revocation while it holds the lock", async () => {
			await h.seed();
			setNow(DUE);
			// The first look finds a token to refresh; the boundary is stamped
			// before the look under the lock, which is the one that revokes.
			let reads = 0;
			h.deps.grantsBoundary = async () => {
				reads += 1;
				return reads === 1 ? null : at(MIN);
			};
			h.deps.audit = (event) =>
				event.type === "federation.grant.revoked" ? new Promise(() => {}) : undefined;
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			expect(await answer).toMatchObject({ code: "grant_revoked", reason: "backstop" });
			expect(await lockIsFree(h)).toBe(true);
		});

		it("tells the composer's logger every cause it turns into an answer, or drops", async () => {
			const causes = async (arrange: () => void | Promise<void>): Promise<string[]> => {
				h = harness();
				setNow(T0);
				await h.seed();
				setNow(DUE);
				h.refresh.mockResolvedValue(refreshed("1", DUE));
				const reported: Array<{ during: string }> = [];
				h.deps.report = (failure) => reported.push(failure);
				await arrange();
				const answer = retrieve();
				await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 500);
				await answer;
				await Promise.all(h.background);
				return [...new Set(reported.map((failure) => failure.during))];
			};
			const down = new Error("redis down");

			expect(await causes(() => void vi.spyOn(h.store, "open").mockRejectedValue(down))).toEqual([
				"open",
			]);
			expect(
				await causes(() => void vi.spyOn(h.store, "acquireRefreshLock").mockRejectedValue(down)),
			).toEqual(["lock"]);
			expect(
				await causes(() => void vi.spyOn(h.store, "replaceCredentials").mockRejectedValue(down)),
			).toEqual(["write"]);
			expect(await causes(() => void vi.spyOn(h.store, "touch").mockRejectedValue(down))).toEqual([
				"touch",
			]);
			expect(
				await causes(() => {
					h.world.boundary = at(MIN);
					vi.spyOn(h.store, "revoke").mockRejectedValue(down);
				}),
			).toEqual(["backstop_revoke"]);
			expect(
				await causes(() => {
					h.refresh.mockRejectedValue(Object.assign(new Error("x"), { error: "invalid_grant" }));
					vi.spyOn(h.store, "requireReauthorization").mockRejectedValue(down);
				}),
			).toEqual(["upstream", "mark"]);
			expect(
				await causes(() => {
					h.deps.background = () => {
						throw new Error("no registry");
					};
				}),
			).toEqual(["background"]);
		});

		it("rejects for a bug in what it was handed, and does not dress it up as an outage", async () => {
			await h.seed();
			h.world.connections.set(connection.name, {
				...connection,
				scopes: 42 as unknown as string[],
			});
			await expect(retrieve()).rejects.toThrow(TypeError);
		});
	});

	describe("a write whose acknowledgement was lost", () => {
		it("is known for the call's own once the record is looked at: refreshed, and audited as such", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const real = h.store.replaceCredentials.bind(h.store);
			vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(async (input) => {
				await real(input);
				throw new Error("connection reset after commit");
			});
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(500);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1", refreshed: true });
			await Promise.all(h.background);
			const told = h.events.map((event) => `${event.type} ${event.outcome}`);
			expect(told).toContain("federation.grant.refreshed success");
			expect(told).not.toContain("federation.grant.refresh_failed write_lost");
		});

		it.each([
			[
				"the same refresh token beside another access token, as an IdP that does not rotate leaves it",
				SECRET,
				"at-theirs",
			],
			["another refresh token beside the same access token", `${SECRET}-theirs`, "at-1"],
		])(
			"is a loss when the write never landed and somebody else's did — %s",
			async (_, refreshToken, accessToken) => {
				const grant = await h.seed();
				setNow(DUE);
				// No rotation: what this call tries to store keeps the stored refresh token.
				h.refresh.mockResolvedValue(refreshed("1", DUE, { refreshToken: undefined }));
				const real = h.store.replaceCredentials.bind(h.store);
				vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(async () => {
					await real({
						grantId: "g-1",
						expectedVersion: grant.version,
						credentials: {
							refreshToken,
							accessToken: {
								value: accessToken,
								tokenType: "Bearer",
								obtainedAt: now(),
								issuedLifetime: 3600,
								scopes: [...SCOPES],
							},
						},
						ineligible: null,
						now: now(),
					});
					throw new Error("blip");
				});
				const answer = retrieve();
				await vi.advanceTimersByTimeAsync(500);
				// Theirs is what is stored, and what is answered — and not as this
				// call's refresh.
				expect(await answer).toMatchObject({ ok: true, accessToken, refreshed: false });
				await Promise.all(h.background);
				const told = h.events.map((event) => `${event.type} ${event.outcome}`);
				expect(told).toContain("federation.grant.refresh_failed write_lost");
				expect(told).not.toContain("federation.grant.refreshed success");
			},
		);

		it("is a loss when somebody else stored the very same credentials: the marker beside them is theirs", async () => {
			// An IdP that does not rotate, and an adapter that answers nonsense: two
			// replicas would store the same refresh token and no access token. What
			// this call tried to store includes its marker, and that one is dated.
			const grant = await h.seed();
			setNow(GONE);
			h.refresh.mockResolvedValue({ refreshToken: SECRET } as FederationGrantRefreshedToken);
			const real = h.store.replaceCredentials.bind(h.store);
			vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(async () => {
				await real({
					grantId: "g-1",
					expectedVersion: grant.version,
					credentials: { refreshToken: SECRET },
					ineligible: {
						reason: "malformed_token_response",
						at: new Date(now().getTime() - 1_000),
						judgedAgainst: 3600,
					},
					now: now(),
				});
				throw new Error("blip");
			});
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(500);
			await answer;
			await Promise.all(h.background);
			const told = h.events.map((event) => `${event.type} ${event.outcome}`);
			expect(told).toContain("federation.grant.refresh_failed write_lost");
			expect(told.filter((entry) => entry.startsWith("federation.grant.refreshed "))).toEqual([]);
		});

		it("is looked for with what is left of the persist budget, and not with a budget of its own", async () => {
			// The lock is sized for the hard deadline plus ONE persist budget (D12).
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			const real = h.store.replaceCredentials.bind(h.store);
			vi.spyOn(h.store, "replaceCredentials").mockImplementationOnce(async (input) => {
				await real(input);
				await new Promise((resolve) => setTimeout(resolve, 2_800));
				throw new Error("connection reset after commit");
			});
			const open = h.store.open.bind(h.store);
			let opens = 0;
			vi.spyOn(h.store, "open").mockImplementation((id, moment) => {
				opens += 1;
				// The first look, the one under the lock — and then the one that
				// settles the lost acknowledgement, which hangs.
				return opens === 3 ? new Promise(() => {}) : open(id, moment);
			});
			let answered = false;
			const answer = retrieve().then((result) => {
				answered = true;
				return result;
			});
			await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + 50);
			expect(answered).toBe(true);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-1" });
		});

		it("is a loss when what is stored is somebody else's", async () => {
			await h.seed();
			setNow(DUE);
			h.refresh.mockResolvedValue(refreshed("1", DUE));
			vi.spyOn(h.store, "replaceCredentials")
				.mockRejectedValueOnce(new Error("blip"))
				.mockImplementationOnce(async () => {
					await h.store.revoke("g-1", "client", now());
					return { ok: false };
				});
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(500);
			expect(await answer).toMatchObject({ code: "grant_revoked" });
			await Promise.all(h.background);
			expect(h.events.map((event) => `${event.type} ${event.outcome}`)).toContain(
				"federation.grant.refresh_failed write_lost",
			);
		});
	});

	describe("what the audit sink is told about a grant that was never authorized", () => {
		it("names no upstream account and no scopes, for there are none", async () => {
			await h.store.createPending({
				id: "g-1",
				subject: "u-1",
				clientId: "agent",
				connection: connection.name,
				intent: { handle: "h-1", expiresAt: at(10 * MIN) },
				now: T0,
			});
			await retrieve();
			await retrieve({ grantId: "g-unknown" });
			expect(h.events).toStrictEqual([
				{
					type: "federation.grant.token.denied",
					correlationId: "req-1",
					grantId: "g-1",
					clientId: "agent",
					subject: "u-1",
					connection: "okta-calendar",
					outcome: "authorization_pending",
				},
				{
					type: "federation.grant.token.denied",
					correlationId: "req-1",
					grantId: "g-unknown",
					clientId: "agent",
					subject: "u-1",
					outcome: "grant_not_found",
				},
			]);
		});
	});

	it("never repeats a secret the upstream echoes as its error code: only codes this provider knows are repeated (D18)", async () => {
		await h.seed();
		setNow(GONE);
		// Exactly the shape of an opaque token, and of an error code.
		h.refresh.mockRejectedValue(Object.assign(new Error("x"), { error: SECRET, status: 400 }));
		const result = await retrieve();
		await Promise.all(h.background);
		expect(result).toStrictEqual({ ok: false, code: "upstream_rejected", reason: "unknown" });
		expect(JSON.stringify(h.events)).not.toContain(SECRET);
	});
});
