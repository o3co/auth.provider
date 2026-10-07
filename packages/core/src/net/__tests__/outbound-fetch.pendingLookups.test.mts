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
import { MAX_PENDING_LOOKUPS as OUTBOUND_MAX_PENDING_LOOKUPS } from "#/net/outbound-fetch.mjs";
import type { OutboundTransport } from "#/net/outbound-transport.mjs";
import { createOutboundFetchForTesting, OutboundFetchError } from "#/testing/outboundFetch.mjs";

const PUBLIC_V4 = "93.184.216.34";

/** A resolver whose every lookup stays outstanding until the test releases it. */
const heldResolver = () => {
	const held: Array<{ readonly hostname: string; readonly release: () => void }> = [];
	let settled = 0;
	return {
		held,
		/** Lookups started and not yet settled. */
		outstanding: () => held.length - settled,
		lookup: (hostname: string): Promise<readonly string[]> =>
			new Promise((resolve) => {
				held.push({
					hostname,
					release: () => {
						settled += 1;
						resolve([PUBLIC_V4]);
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

const fetchOver = (lookup: (hostname: string) => Promise<readonly string[]>, timeoutMs = 50) =>
	createOutboundFetchForTesting({
		config: {},
		source: "request",
		lookup,
		transport: ok,
		timeoutMs,
	});

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
	it("is bounded at a fixed ceiling", () => {
		expect(OUTBOUND_MAX_PENDING_LOOKUPS).toBe(16);
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
