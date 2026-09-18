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
	type Harness,
	HOUR,
	harness,
	limits,
	MIN,
	now,
	refreshed,
	request,
	setNow,
	T0,
} from "./retrieve.harness.mjs";

/**
 * A refresh is an attempt to improve on the stored token, never a condition
 * for answering one that is good. Whatever the attempt came to, the call ends
 * in the ordinary last look (D10): a stored token that serves the request is
 * answered with the life it has, and the attempt's failure only where nothing
 * stored serves it. The look's own verdicts — expired, revoked — come first.
 */
describe("retrieveFederationGrantToken — what a failed refresh leaves the caller with (#593, D10, D12)", () => {
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

	/** Forty minutes in: half spent, twenty minutes left. */
	const HALF_SPENT = at(40 * MIN);
	const outage = () => Object.assign(new Error("x"), { status: 503 });

	describe("a stored token that still serves the request", () => {
		it("is answered when the upstream failed: an outage improves nothing, and takes nothing away", async () => {
			await h.seed();
			setNow(HALF_SPENT);
			h.refresh.mockRejectedValue(outage());
			// Twenty minutes are left and fifty asked: a refresh is wanted, and
			// fails. The caller decides what twenty minutes are worth (D10).
			expect(await retrieve({ minTtlSeconds: 3000 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
				expiresIn: 1200,
				refreshed: false,
			});
			expect(h.refresh).toHaveBeenCalledTimes(1);
			// The failure is still audited as such.
			await Promise.all(h.background);
			expect(h.events.map((event) => `${event.type} ${event.outcome}`)).toContain(
				"federation.grant.refresh_failed temporarily_unavailable/upstream",
			);
		});

		it("is answered, with the life it has, when it has run down and the upstream failed", async () => {
			await h.seed();
			setNow(at(HOUR - 15_000));
			h.refresh.mockRejectedValue(outage());
			expect(await retrieve()).toMatchObject({ ok: true, accessToken: "at-0", expiresIn: 15 });
		});

		it("is answered when the caller stops waiting at the soft deadline, while the refresh goes on", async () => {
			await h.seed();
			setNow(HALF_SPENT);
			let resolve!: (value: FederationGrantRefreshedToken) => void;
			h.refresh.mockReturnValueOnce(
				new Promise((res) => {
					resolve = res;
				}),
			);
			const answer = retrieve({ minTtlSeconds: 3000 });
			await vi.advanceTimersByTimeAsync(limits.upstreamTimeoutMs + 50);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-0", refreshed: false });
			resolve(refreshed("late", now()));
			await vi.advanceTimersByTimeAsync(100);
			await Promise.all(h.background);
			expect(await retrieve()).toMatchObject({ accessToken: "at-late", refreshed: false });
		});

		it("is answered when another replica holds the lock past the wait, whatever it is doing", async () => {
			await h.seed();
			setNow(HALF_SPENT);
			const theirs = await h.store.acquireRefreshLock("g-1", { ttlMs: 60_000, waitForMs: 0 });
			if (!theirs.acquired) throw new Error("fixture: the lock was not free");
			const answer = retrieve({ minTtlSeconds: 3000 });
			await vi.advanceTimersByTimeAsync(limits.lockWaitMs + 100);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-0", refreshed: false });
			await theirs.release();
		});

		it("is answered when the store cannot even be asked for the lock", async () => {
			await h.seed();
			setNow(HALF_SPENT);
			vi.spyOn(h.store, "acquireRefreshLock").mockRejectedValueOnce(new Error("redis down"));
			expect(await retrieve({ minTtlSeconds: 3000 })).toMatchObject({
				ok: true,
				accessToken: "at-0",
			});
		});

		it("is answered when the look under the lock has used up the lease", async () => {
			await h.seed();
			setNow(HALF_SPENT);
			let reads = 0;
			h.deps.grantsBoundary = async () => {
				reads += 1;
				if (reads === 2) await new Promise((resolve) => setTimeout(resolve, 12_000));
				return null;
			};
			const answer = retrieve({ minTtlSeconds: 3000 });
			await vi.advanceTimersByTimeAsync(12_000);
			expect(await answer).toMatchObject({ ok: true, accessToken: "at-0" });
			expect(h.refresh).not.toHaveBeenCalled();
		});

		it("is NOT answered for a scope it does not carry: the failure is what the caller is told", async () => {
			await h.seed();
			setNow(HALF_SPENT);
			h.refresh.mockRejectedValue(outage());
			expect(await retrieve({ scope: ["calendar.write"] })).toStrictEqual({
				ok: false,
				code: "temporarily_unavailable",
				reason: "upstream",
			});
		});
	});

	describe("the token the call fetched itself", () => {
		it("answers invalid_scope when it lacks the asserted scope, even when the last look finds it half spent: the upstream was asked, and that is what it gave", async () => {
			// Four-second tokens, and a last look whose boundary read takes three:
			// the call's own token is half spent by the time it is judged.
			await h.seed();
			setNow(at(HOUR - 15_000));
			h.refresh.mockImplementation(async () =>
				refreshed("1", now(), {
					expiresIn: 4,
					expiresAt: new Date(now().getTime() + 4_000),
					scope: "openid calendar.read",
				}),
			);
			let reads = 0;
			h.deps.grantsBoundary = async () => {
				reads += 1;
				if (reads === 3) await new Promise((resolve) => setTimeout(resolve, 3_000));
				return null;
			};
			const answer = retrieve({ scope: ["calendar.write"] });
			await vi.advanceTimersByTimeAsync(3_100);
			expect(await answer).toStrictEqual({ ok: false, code: "invalid_scope" });
		});
	});

	describe("the look's own verdict comes before the attempt's", () => {
		it("reports an expiry that landed during the upstream call, even when the upstream answered invalid_grant and the record was marked", async () => {
			// `requireReauthorization` marks an expired record on purpose (D1); the
			// answer must not send the caller to a renewal that has to be refused.
			await h.seed({ expiresAt: at(HOUR) });
			setNow(at(HOUR - 15_000));
			let reject!: (error: unknown) => void;
			h.refresh.mockReturnValueOnce(
				new Promise((_, rej) => {
					reject = rej;
				}),
			);
			const answer = retrieve();
			await vi.advanceTimersByTimeAsync(100);
			setNow(at(HOUR + 1_000));
			reject(Object.assign(new Error("x"), { error: "invalid_grant" }));
			expect(await answer).toStrictEqual({
				ok: false,
				code: "grant_expired",
				reason: "consented_lifetime",
			});
			expect((await h.store.find("g-1", now()))?.status).toBe("reauthorization_required");
		});

		it("reports a revocation that landed during the upstream call, whatever the upstream answered", async () => {
			await h.seed();
			setNow(HALF_SPENT);
			let reject!: (error: unknown) => void;
			h.refresh.mockReturnValueOnce(
				new Promise((_, rej) => {
					reject = rej;
				}),
			);
			const answer = retrieve({ minTtlSeconds: 3000 });
			await vi.advanceTimersByTimeAsync(100);
			await h.store.revoke("g-1", "client", now());
			reject(outage());
			expect(await answer).toMatchObject({ ok: false, code: "grant_revoked" });
		});
	});
});
