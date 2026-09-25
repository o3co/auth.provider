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
 * A `temporarily_unavailable` answer carries the reported failure it was
 * turned from (`failure`), so that the route answering it can log the outage
 * once, with its cause — and a failure the answer did not carry is still
 * reported, for the route to log as what it absorbed.
 *
 * The failure is the very object the `report` seam was handed, and it is not
 * enumerable: nothing that serialises or spreads the answer — a response, an
 * audit event — can carry what an upstream or a store put on the error.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	type FederationGrantRetrievalFailure,
	retrieveFederationGrantToken,
} from "#/federation-grants/retrieve.mjs";
import type { FederationGrantTokenResult } from "#/federation-grants/types.mjs";
import {
	at,
	type Harness,
	HOUR,
	harness,
	limits,
	refreshed,
	request,
	setNow,
	T0,
} from "./retrieve.harness.mjs";

const failureOf = (
	result: FederationGrantTokenResult,
): FederationGrantRetrievalFailure | undefined =>
	result.ok || result.code !== "temporarily_unavailable" ? undefined : result.failure;

describe("retrieveFederationGrantToken — the cause a 503 was turned from", () => {
	let h: Harness;
	let reported: FederationGrantRetrievalFailure[];

	beforeEach(() => {
		vi.useFakeTimers();
		setNow(T0);
		h = harness();
		reported = [];
		h.deps.report = (failure) => {
			reported.push(failure);
		};
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	const retrieve = (over: Partial<typeof request> = {}) =>
		retrieveFederationGrantToken(h.deps, { ...request, ...over });

	/** The answer after every timer a refresh may start has run. */
	const settled = async (): Promise<FederationGrantTokenResult> => {
		const answer = retrieve();
		await vi.advanceTimersByTimeAsync(limits.persistRetryBudgetMs + limits.lockWaitMs + 4_000);
		return await answer;
	};

	it("carries the store's failure to read the grant, as the very failure it reported", async () => {
		await h.seed();
		const down = new Error("redis down");
		vi.spyOn(h.store, "open").mockRejectedValue(down);
		const result = await retrieve();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		const failure = failureOf(result);
		expect(failure).toMatchObject({
			during: "open",
			error: down,
			grantId: "g-1",
			correlationId: "req-1",
		});
		expect(reported).toEqual([failure]);
		expect(reported[0]).toBe(failure);
	});

	it("keeps it out of anything that serialises or spreads the answer", async () => {
		await h.seed();
		vi.spyOn(h.store, "open").mockRejectedValue(
			Object.assign(new Error("redis down"), { body: "SENTINEL-body" }),
		);
		const result = await retrieve();
		expect(failureOf(result)).toBeDefined();
		expect(Object.keys(result)).not.toContain("failure");
		expect(JSON.stringify(result)).not.toContain("SENTINEL");
		expect({ ...result }).not.toHaveProperty("failure");
	});

	it("carries a boundary that cannot be read, for a grant whose answer needed it", async () => {
		await h.seed();
		const down = new Error("boundary down");
		h.world.boundary = down;
		const result = await retrieve();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		expect(failureOf(result)).toMatchObject({ during: "boundary", error: down });
		expect(reported).toHaveLength(1);
	});

	it("carries a backstop that could not be written down", async () => {
		await h.seed();
		setNow(at(10 * 60_000));
		h.world.boundary = at(5 * 60_000);
		const down = new Error("write refused");
		vi.spyOn(h.store, "revoke").mockRejectedValue(down);
		const result = await retrieve();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		expect(failureOf(result)).toMatchObject({ during: "backstop_revoke", error: down });
	});

	it("carries nothing for a key missing from the ring: nothing was thrown", async () => {
		const grant = await h.seed();
		vi.spyOn(h.store, "open").mockResolvedValue({
			grant,
			credentials: { state: "key_unavailable" },
		});
		const result = await retrieve();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "key_unavailable" });
		expect(failureOf(result)).toBeUndefined();
		expect(reported).toEqual([]);
	});

	it("carries a lock the store could not give, when the last look has nothing to answer with", async () => {
		await h.seed();
		setNow(at(HOUR));
		const down = new Error("lock refused");
		vi.spyOn(h.store, "acquireRefreshLock").mockRejectedValue(down);
		const result = await settled();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		expect(failureOf(result)).toMatchObject({ during: "lock", error: down });
		expect(reported.map((failure) => failure.during)).toEqual(["lock"]);
	});

	it("carries an upstream that could not be reached, and reports a stamp that could not be written beside it", async () => {
		await h.seed();
		setNow(at(HOUR));
		const unreachable = Object.assign(new TypeError("fetch failed"), {
			cause: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }),
		});
		h.refresh.mockRejectedValue(unreachable);
		const stampDown = new Error("stamp refused");
		vi.spyOn(h.store, "noteRefreshFailure").mockRejectedValue(stampDown);
		const result = await settled();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
		const failure = failureOf(result);
		expect(failure).toMatchObject({ during: "upstream", error: unreachable });
		// The stamp's own failure is reported, and is not what the answer carries.
		const mark = reported.find((reportedFailure) => reportedFailure.during === "mark");
		expect(mark).toMatchObject({ error: stampDown });
		expect(mark).not.toBe(failure);
	});

	it("reports a write it retried once per kind of failure, with the last cause and how many attempts, and carries that one", async () => {
		await h.seed();
		setNow(at(HOUR));
		h.refresh.mockResolvedValue(refreshed("1", at(HOUR)));
		let attempt = 0;
		vi.spyOn(h.store, "replaceCredentials").mockImplementation(async () => {
			attempt += 1;
			throw new Error(`write refused ${attempt}`);
		});
		const result = await settled();
		expect(attempt).toBeGreaterThan(1);
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		const writes = reported.filter((failure) => failure.during === "write");
		expect(writes).toHaveLength(1);
		expect(writes[0]?.error).toEqual(new Error(`write refused ${attempt}`));
		expect(writes[0]?.attempts).toBe(attempt);
		expect(failureOf(result)).toBe(writes[0]);
	});

	it("reports each distinct kind of write failure once, and carries the last kind", async () => {
		await h.seed();
		setNow(at(HOUR));
		h.refresh.mockResolvedValue(refreshed("1", at(HOUR)));
		let attempt = 0;
		const reset = () => Object.assign(new Error("connection reset"), { code: "ECONNRESET" });
		vi.spyOn(h.store, "replaceCredentials").mockImplementation(async () => {
			attempt += 1;
			throw attempt === 1 ? new TypeError("the record is not one") : reset();
		});
		const result = await settled();
		expect(attempt).toBeGreaterThan(2);
		const writes = reported.filter((failure) => failure.during === "write");
		expect(writes.map((failure) => [(failure.error as Error).name, failure.attempts])).toEqual([
			["TypeError", undefined],
			["Error", attempt - 1],
		]);
		expect(failureOf(result)).toBe(writes[1]);
	});

	it("carries a write that hangs as not answered, and reports an earlier throw on its own", async () => {
		await h.seed();
		setNow(at(HOUR));
		h.refresh.mockResolvedValue(refreshed("1", at(HOUR)));
		const refused = new Error("write refused");
		vi.spyOn(h.store, "replaceCredentials")
			.mockRejectedValueOnce(refused)
			.mockReturnValue(new Promise(() => {}));
		const result = await settled();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		const failure = failureOf(result);
		expect(failure).toMatchObject({ during: "write" });
		expect(failure?.error).toEqual(new Error("not answered in time; no longer waited for"));
		// The throw before it is reported, and is not what the answer carries.
		const earlier = reported.find((reportedFailure) => reportedFailure.error === refused);
		expect(earlier).toMatchObject({ during: "write" });
		expect(earlier).not.toBe(failure);
	});

	it("carries a write that hangs on its first attempt as not answered", async () => {
		await h.seed();
		setNow(at(HOUR));
		h.refresh.mockResolvedValue(refreshed("1", at(HOUR)));
		vi.spyOn(h.store, "replaceCredentials").mockReturnValue(new Promise(() => {}));
		const result = await settled();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		expect(failureOf(result)).toMatchObject({ during: "write" });
		expect(reported.filter((failure) => failure.during === "write")).toEqual([failureOf(result)]);
	});

	it("carries a reauthorization mark that hangs as not answered", async () => {
		await h.seed();
		setNow(at(HOUR));
		h.refresh.mockRejectedValue(Object.assign(new Error("refused"), { error: "invalid_grant" }));
		vi.spyOn(h.store, "requireReauthorization").mockReturnValue(new Promise(() => {}));
		const result = await settled();
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "storage" });
		const failure = failureOf(result);
		expect(failure).toMatchObject({ during: "mark" });
		expect(failure?.error).toEqual(new Error("not answered in time; no longer waited for"));
	});

	it("reports the upstream the hard deadline gave up on, after the caller was answered", async () => {
		await h.seed();
		setNow(at(HOUR));
		h.refresh.mockReturnValue(new Promise(() => {}));
		const answer = retrieve();
		await vi.advanceTimersByTimeAsync(limits.upstreamTimeoutMs + 100);
		expect(await answer).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
		expect(reported).toEqual([]);
		await vi.advanceTimersByTimeAsync(limits.upstreamHardTimeoutMs);
		await Promise.all(h.background);
		expect(reported.map((failure) => failure.during)).toEqual(["upstream"]);
		expect(reported[0]?.error).toEqual(new Error("not answered in time; no longer waited for"));
	});

	it("carries nothing when the upstream did not answer before the caller stopped waiting", async () => {
		await h.seed();
		setNow(at(HOUR));
		h.refresh.mockReturnValue(new Promise(() => {}));
		const answer = retrieve();
		await vi.advanceTimersByTimeAsync(limits.upstreamTimeoutMs + 100);
		const result = await answer;
		expect(result).toMatchObject({ code: "temporarily_unavailable", reason: "upstream" });
		expect(failureOf(result)).toBeUndefined();
		await vi.advanceTimersByTimeAsync(limits.upstreamHardTimeoutMs);
	});
});
