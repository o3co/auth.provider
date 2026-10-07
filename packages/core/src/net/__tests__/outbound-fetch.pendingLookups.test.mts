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
 * The bound on host-name resolutions a fetch has outstanding: a resolution
 * the deadline gave up on still counts until it settles, and a call that
 * finds the bound reached waits for one, within its own deadline, rather
 * than starting another.
 */

import { describe, expect, it } from "vitest";
import {
	buildOutboundFetch,
	createLookupPermits,
	lookupCeilingOf,
	MAX_REQUEST_WAITING_LOOKUPS,
	MAX_WAITING_LOOKUPS as OUTBOUND_MAX_WAITING_LOOKUPS,
} from "#/net/outbound-fetch.mjs";
import type { OutboundTransport } from "#/net/outbound-transport.mjs";
import { createOutboundFetchForTesting, OutboundFetchError } from "#/testing/outboundFetch.mjs";

const PUBLIC_V4 = "93.184.216.34";

/** The places a testing fetch's own pool has: as many as the process's. */
const OUTBOUND_MAX_PENDING_LOOKUPS = lookupCeilingOf(process.env.UV_THREADPOOL_SIZE);

/** A resolver whose every lookup stays outstanding until the test releases (or fails) it. */
const heldResolver = () => {
	const held: Array<{
		readonly hostname: string;
		readonly release: () => void;
		readonly fail: () => void;
	}> = [];
	let settled = 0;
	return {
		held,
		/** Lookups started and not yet settled. */
		outstanding: () => held.length - settled,
		lookup: (hostname: string): Promise<readonly string[]> =>
			new Promise((resolve, reject) => {
				held.push({
					hostname,
					release: () => {
						settled += 1;
						resolve([PUBLIC_V4]);
					},
					fail: () => {
						settled += 1;
						reject(Object.assign(new Error("timed out"), { code: "ETIMEOUT" }));
					},
				});
			}),
	};
};

/** A transport that answers 200 with an empty body. */
const ok: OutboundTransport = async () => ({
	status: 200,
	statusText: "OK",
	headers: [],
	body: (async function* () {})(),
	close: () => undefined,
});

/** A transport that answers 200 and then never ends the body; counts the answers it closed. */
const stalling = () => {
	let closed = 0;
	const transport: OutboundTransport = async () => ({
		status: 200,
		statusText: "OK",
		headers: [],
		body: (async function* () {
			await new Promise(() => undefined);
		})(),
		close: () => {
			closed += 1;
		},
	});
	return { transport, closed: () => closed };
};

const fetchOver = (
	lookup: (hostname: string) => Promise<readonly string[]>,
	timeoutMs = 50,
	transport: OutboundTransport = ok,
) =>
	createOutboundFetchForTesting({
		config: {},
		source: "registration",
		lookup,
		transport,
		timeoutMs,
	});

/** Holds every place of `fetch`'s with a call whose lookup stays outstanding. */
const fillPlaces = async (fetch: typeof globalThis.fetch, prefix = "held") => {
	const calls = Array.from({ length: OUTBOUND_MAX_PENDING_LOOKUPS }, (_, i) =>
		fetch(`https://${prefix}${i}.example/doc`),
	);
	for (const call of calls) call.catch(() => undefined);
	await flush();
	return calls;
};

const reasonOf = async (promise: Promise<unknown>): Promise<string> => {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(OutboundFetchError);
		return (err as OutboundFetchError).reason;
	}
	throw new Error("expected a rejection");
};

/** Lets settled lookups' continuations run. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("outstanding host-name resolutions", () => {
	it("is bounded two below the threadpool size, read from UV_THREADPOOL_SIZE as libuv reads it", () => {
		// Absent: libuv's default of 4.
		expect(lookupCeilingOf(undefined)).toBe(2);
		// Present: atoi — leading digits, else 0 — then 0 reads as 1 and past 1024 as 1024.
		expect(lookupCeilingOf("")).toBe(1);
		expect(lookupCeilingOf("0")).toBe(1);
		expect(lookupCeilingOf("four")).toBe(1);
		expect(lookupCeilingOf("8abc")).toBe(6);
		expect(lookupCeilingOf(" 8")).toBe(6);
		expect(lookupCeilingOf("+8")).toBe(6);
		expect(lookupCeilingOf("4.9")).toBe(2);
		expect(lookupCeilingOf("2000")).toBe(1022);
		expect(lookupCeilingOf("1024")).toBe(1022);
		expect(lookupCeilingOf("16")).toBe(14);
		expect(lookupCeilingOf("3")).toBe(1);
		expect(lookupCeilingOf("2")).toBe(1);
		expect(lookupCeilingOf("1")).toBe(1);
		// A negative count is a huge unsigned one to libuv, so it is clamped to 1024.
		expect(lookupCeilingOf("-4")).toBe(1022);
	});

	it("keeps a resolution the deadline gave up on counted, so the next call starts none and times out", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup);
		const timedOut = await Promise.all(
			Array.from({ length: OUTBOUND_MAX_PENDING_LOOKUPS }, (_, i) =>
				reasonOf(fetch(`https://rp${i}.example/doc`)),
			),
		);
		expect(timedOut.every((reason) => reason === "timeout")).toBe(true);
		expect(resolver.outstanding()).toBe(OUTBOUND_MAX_PENDING_LOOKUPS);

		const started = Date.now();
		expect(await reasonOf(fetch("https://one-more.example/doc"))).toBe("timeout");
		expect(Date.now() - started).toBeGreaterThanOrEqual(40);
		expect(resolver.held).toHaveLength(OUTBOUND_MAX_PENDING_LOOKUPS);
		expect(resolver.held.some((h) => h.hostname === "one-more.example")).toBe(false);

		// The call that gave up waiting holds nothing: one settled lookup frees exactly one place.
		resolver.held[0]?.release();
		await flush();
		const next = fetch("https://after.example/doc");
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("after.example");
		resolver.held.at(-1)?.release();
		await expect(next).resolves.toHaveProperty("status", 200);
	});

	it("lets a waiting call resolve once a held resolution settles", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup, 5_000);
		const held = Array.from({ length: OUTBOUND_MAX_PENDING_LOOKUPS }, (_, i) =>
			fetch(`https://held${i}.example/doc`),
		);
		await flush();
		expect(resolver.outstanding()).toBe(OUTBOUND_MAX_PENDING_LOOKUPS);
		const waiting = fetch("https://next.example/doc");
		await flush();
		expect(resolver.held).toHaveLength(OUTBOUND_MAX_PENDING_LOOKUPS);

		resolver.held[0]?.release();
		await expect(held[0]).resolves.toHaveProperty("status", 200);
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("next.example");
		expect(resolver.outstanding()).toBe(OUTBOUND_MAX_PENDING_LOOKUPS);
		resolver.held.at(-1)?.release();
		await expect(waiting).resolves.toHaveProperty("status", 200);

		for (const h of resolver.held) h.release();
		await Promise.all(held);
	});

	it("frees a resolution the deadline gave up on when it settles, not before", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup);
		await Promise.all(
			Array.from({ length: OUTBOUND_MAX_PENDING_LOOKUPS }, (_, i) =>
				reasonOf(fetch(`https://rp${i}.example/doc`)),
			),
		);
		resolver.held[0]?.release();
		await flush();
		const next = fetch("https://after.example/doc");
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("after.example");
		resolver.held.at(-1)?.release();
		await expect(next).resolves.toHaveProperty("status", 200);
	});

	it("does not count an address literal, nor a call refused before resolution", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup);
		await Promise.all(
			Array.from({ length: OUTBOUND_MAX_PENDING_LOOKUPS }, (_, i) =>
				reasonOf(fetch(`https://rp${i}.example/doc`)),
			),
		);
		await expect(fetch(`https://${PUBLIC_V4}/doc`)).resolves.toHaveProperty("status", 200);
		expect(await reasonOf(fetch("https://127.0.0.1/doc"))).not.toBe("timeout");
		expect(await reasonOf(fetch("ftp://rp.example/doc"))).not.toBe("timeout");
		expect(resolver.held).toHaveLength(OUTBOUND_MAX_PENDING_LOOKUPS);
	});

	it("bounds the calls waiting for a place, and fails one past that bound with timeout at once", async () => {
		expect(OUTBOUND_MAX_WAITING_LOOKUPS).toBe(64);
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup, 5_000);
		await fillPlaces(fetch);
		const waiting = Array.from({ length: OUTBOUND_MAX_WAITING_LOOKUPS }, (_, i) =>
			fetch(`https://wait${i}.example/doc`),
		);
		for (const call of waiting) call.catch(() => undefined);
		await flush();

		const started = Date.now();
		const burst = await Promise.all(
			Array.from({ length: 20 }, (_, i) => reasonOf(fetch(`https://over${i}.example/doc`))),
		);
		expect(burst.every((reason) => reason === "timeout")).toBe(true);
		expect(Date.now() - started).toBeLessThan(1_000);
		expect(resolver.held).toHaveLength(OUTBOUND_MAX_PENDING_LOOKUPS);

		// Every waiter is still served, in turn, as places come free.
		for (let i = 0; i < OUTBOUND_MAX_WAITING_LOOKUPS + OUTBOUND_MAX_PENDING_LOOKUPS; i += 1) {
			resolver.held[i]?.release();
			await flush();
		}
		const answers = await Promise.all(waiting);
		expect(answers.every((answer) => answer.status === 200)).toBe(true);
		expect(resolver.held.every((h) => !h.hostname.startsWith("over"))).toBe(true);
	});

	it("serves waiting calls in the order they arrived", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup, 5_000);
		const held = await fillPlaces(fetch);
		const queued = ["a", "b", "c"].map((name) => fetch(`https://${name}.example/doc`));
		await flush();
		for (let i = 0; i < 3; i += 1) {
			resolver.held[i]?.release();
			await flush();
		}
		expect(resolver.held.slice(-3).map((h) => h.hostname)).toEqual([
			"a.example",
			"b.example",
			"c.example",
		]);
		for (const h of resolver.held) h.release();
		await Promise.all([...held, ...queued]);
	});

	it("drops a waiting call its caller aborts, and gives the next place to the call behind it", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup, 5_000);
		const held = await fillPlaces(fetch);
		const caller = new AbortController();
		const reason = new Error("caller gave up");
		const aborted = fetch("https://aborted.example/doc", { signal: caller.signal });
		const behind = fetch("https://behind.example/doc");
		await flush();
		caller.abort(reason);
		await expect(aborted).rejects.toBe(reason);

		resolver.held[0]?.release();
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("behind.example");
		expect(resolver.held.some((h) => h.hostname === "aborted.example")).toBe(false);
		for (const h of resolver.held) h.release();
		await Promise.all([...held, behind]);
	});

	it("passes a place on, starting nothing, when the call it was handed to aborted in the handoff", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup, 5_000);
		const held = await fillPlaces(fetch);
		const caller = new AbortController();
		const reason = new Error("caller gave up");
		const handed = fetch("https://handed.example/doc", { signal: caller.signal });
		handed.catch(() => undefined);
		const behind = fetch("https://behind.example/doc");
		await flush();

		// The settled lookup hands its place over in a microtask; the abort lands
		// after that, before the call it was handed to resumes.
		resolver.held[0]?.release();
		queueMicrotask(() => caller.abort(reason));
		await expect(handed).rejects.toBe(reason);
		await flush();
		expect(resolver.held.some((h) => h.hostname === "handed.example")).toBe(false);
		expect(resolver.held.at(-1)?.hostname).toBe("behind.example");
		expect(resolver.outstanding()).toBe(OUTBOUND_MAX_PENDING_LOOKUPS);
		for (const h of resolver.held) h.release();
		await Promise.all([...held, behind]);
	});

	it("frees the place of a lookup that throws synchronously", async () => {
		let calls = 0;
		const fetch = fetchOver((): Promise<readonly string[]> => {
			calls += 1;
			throw Object.assign(new Error("bad name"), { code: "EBADNAME" });
		});
		for (let i = 0; i < OUTBOUND_MAX_PENDING_LOOKUPS + 2; i += 1) {
			expect(await reasonOf(fetch(`https://rp${i}.example/doc`))).toBe("resolution_failed");
		}
		expect(calls).toBe(OUTBOUND_MAX_PENDING_LOOKUPS + 2);
	});

	it("frees the place of a lookup that fails after its call timed out, without an unhandled rejection", async () => {
		const resolver = heldResolver();
		const fetch = fetchOver(resolver.lookup);
		await Promise.all(
			Array.from({ length: OUTBOUND_MAX_PENDING_LOOKUPS }, (_, i) =>
				reasonOf(fetch(`https://rp${i}.example/doc`)),
			),
		);
		resolver.held[0]?.fail();
		await flush();
		const next = fetch("https://after.example/doc");
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("after.example");
		resolver.held.at(-1)?.release();
		await expect(next).resolves.toHaveProperty("status", 200);
	});

	it("holds a call that waited for a place to its one deadline, through a body that stalls", async () => {
		const resolver = heldResolver();
		const body = stalling();
		const fetch = fetchOver(resolver.lookup, 300, body.transport);
		await fillPlaces(fetch);
		const started = Date.now();
		const queued = reasonOf(fetch("https://queued.example/doc"));
		await new Promise((resolve) => setTimeout(resolve, 100));
		resolver.held[0]?.release();
		expect(await queued).toBe("timeout");
		const elapsed = Date.now() - started;
		expect(elapsed).toBeGreaterThanOrEqual(250);
		expect(elapsed).toBeLessThan(600);
		expect(resolver.held.some((h) => h.hostname === "queued.example")).toBe(true);
		expect(body.closed()).toBeGreaterThanOrEqual(1);
	});

	it("leaves a fetch whose resolutions settle in time as it was", async () => {
		const lookups: string[] = [];
		const fetch = fetchOver(async (hostname) => {
			lookups.push(hostname);
			return [PUBLIC_V4];
		});
		const answers = await Promise.all(
			Array.from({ length: OUTBOUND_MAX_PENDING_LOOKUPS * 3 }, (_, i) =>
				fetch(`https://rp${i}.example/doc`),
			),
		);
		expect(answers.every((answer) => answer.status === 200)).toBe(true);
		expect(lookups).toHaveLength(OUTBOUND_MAX_PENDING_LOOKUPS * 3);
	});

	it("frees a resolution that fails, as one that answers", async () => {
		let calls = 0;
		const fetch = fetchOver(async () => {
			calls += 1;
			throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
		});
		for (let i = 0; i < OUTBOUND_MAX_PENDING_LOOKUPS + 2; i += 1) {
			expect(await reasonOf(fetch(`https://rp${i}.example/doc`))).toBe("resolution_failed");
		}
		expect(calls).toBe(OUTBOUND_MAX_PENDING_LOOKUPS + 2);
	});
});

describe("the share of lookups for URLs a request names", () => {
	/** A request-source fetch and a registration-source fetch over one pool of `max` places. */
	const overOnePool = (
		max: number,
		lookup: (hostname: string) => Promise<readonly string[]>,
		timeoutMs = 50,
	) => {
		const lookups = createLookupPermits(max);
		const build = (source: "request" | "registration") =>
			buildOutboundFetch(
				{ config: {}, source, timeoutMs },
				{ lookup, lookups, transport: ok },
			) as typeof globalThis.fetch;
		return { request: build("request"), registration: build("registration") };
	};

	it("is one lookup outstanding, counted until it settles, whatever the pool", async () => {
		const resolver = heldResolver();
		const { request } = overOnePool(14, resolver.lookup);
		const reasons = await Promise.all(
			Array.from({ length: 10 }, (_, i) => reasonOf(request(`https://doc${i}.example/c.json`))),
		);
		expect(reasons.every((reason) => reason === "timeout")).toBe(true);
		expect(resolver.held).toHaveLength(1);
		resolver.held[0]?.release();
		await flush();
		const next = request("https://after.example/c.json");
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("after.example");
		resolver.held.at(-1)?.release();
		await expect(next).resolves.toHaveProperty("status", 200);
	});

	it("leaves the rest of the pool to registrations: lookups nobody waits for no longer starve them", async () => {
		const blackhole = heldResolver();
		const { request, registration } = overOnePool(2, (hostname) =>
			hostname.startsWith("doc") ? blackhole.lookup(hostname) : Promise.resolve([PUBLIC_V4]),
		);
		await Promise.all([
			reasonOf(request("https://doc1.example/c.json")),
			reasonOf(request("https://doc2.example/c.json")),
		]);
		expect(blackhole.outstanding()).toBe(1);
		await expect(registration("https://rp.example/jwks")).resolves.toHaveProperty("status", 200);
		await expect(registration("https://rp2.example/jwks")).resolves.toHaveProperty("status", 200);
	});

	it("hands a freed place to a waiting registration ahead of a request whose share is full", async () => {
		const resolver = heldResolver();
		const { request, registration } = overOnePool(2, resolver.lookup, 5_000);
		const r1 = request("https://r1.example/c.json");
		const g1 = registration("https://g1.example/jwks");
		await flush();
		const r2 = request("https://r2.example/c.json");
		const g2 = registration("https://g2.example/jwks");
		await flush();
		expect(resolver.held.map((h) => h.hostname)).toEqual(["r1.example", "g1.example"]);

		resolver.held[1]?.release(); // g1 settles: r2 arrived first, but the request share is full
		await expect(g1).resolves.toHaveProperty("status", 200);
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("g2.example");

		resolver.held[0]?.release(); // r1 settles: now r2 may go
		await expect(r1).resolves.toHaveProperty("status", 200);
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("r2.example");
		for (const h of resolver.held) h.release();
		await Promise.all([r2, g2]);
	});

	it("bounds the requests waiting below the whole queue, keeping room for registrations to wait", async () => {
		expect(MAX_REQUEST_WAITING_LOOKUPS).toBe(48);
		const resolver = heldResolver();
		const { request, registration } = overOnePool(2, resolver.lookup, 5_000);
		const held = [request("https://r0.example/c.json"), registration("https://g0.example/jwks")];
		await flush();
		const waitingRequests = Array.from({ length: MAX_REQUEST_WAITING_LOOKUPS }, (_, i) =>
			request(`https://wait${i}.example/c.json`),
		);
		for (const call of waitingRequests) call.catch(() => undefined);
		await flush();
		const begun = Date.now();
		expect(await reasonOf(request("https://over.example/c.json"))).toBe("timeout");
		expect(Date.now() - begun).toBeLessThan(1_000);

		// A registration still waits for a place rather than failing.
		const queued = registration("https://g1.example/jwks");
		await flush();
		resolver.held[1]?.release();
		await flush();
		expect(resolver.held.at(-1)?.hostname).toBe("g1.example");
		for (let i = 0; i < 60; i += 1) {
			for (const h of resolver.held) h.release();
			await flush();
		}
		await Promise.all([...held, ...waitingRequests, queued]);
	});

	it("is none when the pool has one place: a request fails with timeout at once, a registration resolves", async () => {
		const resolver = heldResolver();
		const { request, registration } = overOnePool(
			1,
			async (hostname) => {
				resolver.held.push({ hostname, release: () => undefined, fail: () => undefined });
				return [PUBLIC_V4];
			},
			5_000,
		);
		const begun = Date.now();
		expect(await reasonOf(request("https://doc.example/c.json"))).toBe("timeout");
		expect(Date.now() - begun).toBeLessThan(1_000);
		await expect(registration("https://rp.example/jwks")).resolves.toHaveProperty("status", 200);
		expect(resolver.held.map((h) => h.hostname)).toEqual(["rp.example"]);
	});
});
