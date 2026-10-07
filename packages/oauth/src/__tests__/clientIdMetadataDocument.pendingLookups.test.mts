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
 * Fresh document URLs whose host names never resolve: each request answers
 * at its deadline, and the resolutions it gave up on stay counted by the
 * outbound fetch, so however many ids a caller invents, the resolutions
 * outstanding stop at the fetch's ceiling.
 */

import type { Logger } from "@o3co/auth-provider-core";
import {
	createOutboundFetchForTesting,
	createTestOutboundPolicy,
	type OutboundTransport,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import {
	createClientIdMetadataDocumentResolver,
	DEFAULT_CIMD_MAX_CONCURRENT_FETCHES,
} from "#/clients/clientIdMetadataDocument.mjs";

/** The outbound fetch's fixed ceiling on outstanding resolutions (core's `MAX_PENDING_LOOKUPS`). */
const CEILING = 16;

const unreachable: OutboundTransport = () => new Promise(() => undefined);

/** A logger that records each warning's message. */
const logger = (warned: string[]): Logger => {
	const ignore = () => undefined;
	return {
		trace: ignore,
		debug: ignore,
		info: ignore,
		warn: (_fields: unknown, message?: string) => {
			warned.push(String(message));
		},
		error: ignore,
		fatal: ignore,
		child: () => logger(warned),
	} as unknown as Logger;
};

describe("fresh document URLs whose host names never resolve", () => {
	it("answer at their deadline and never push outstanding resolutions past the ceiling", async () => {
		let started = 0;
		const outboundPolicy = createTestOutboundPolicy();
		const resolver = createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy,
			fetch: createOutboundFetchForTesting({
				policy: outboundPolicy,
				source: "request",
				timeoutMs: 30,
				lookup: () => {
					started += 1;
					return new Promise(() => undefined);
				},
				transport: unreachable,
			}),
		});

		const rounds = Math.ceil((CEILING * 3) / DEFAULT_CIMD_MAX_CONCURRENT_FETCHES);
		let id = 0;
		for (let round = 0; round < rounds; round += 1) {
			const begun = Date.now();
			const answers = await Promise.all(
				Array.from({ length: DEFAULT_CIMD_MAX_CONCURRENT_FETCHES }, () => {
					id += 1;
					return resolver.resolve(`https://c${id}.example/client.json`);
				}),
			);
			expect(answers.every((answer) => answer === null)).toBe(true);
			expect(Date.now() - begun).toBeLessThan(2_000);
			expect(started).toBeLessThanOrEqual(CEILING);
		}
		expect(id).toBeGreaterThan(CEILING * 2);
		expect(started).toBe(CEILING);
	});

	it("sent all at once, stay within both bounds and are all answered within the deadlines", async () => {
		let lookups = 0;
		let fetches = 0;
		const warned: string[] = [];
		const outboundPolicy = createTestOutboundPolicy();
		const outbound = createOutboundFetchForTesting({
			policy: outboundPolicy,
			source: "request",
			timeoutMs: 30,
			lookup: () => {
				lookups += 1;
				return new Promise(() => undefined);
			},
			transport: unreachable,
		});
		const resolver = createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy,
			timeoutMs: 30,
			logger: logger(warned),
			fetch: ((input: string | URL | Request, init?: RequestInit) => {
				fetches += 1;
				return outbound(input, init);
			}) as typeof fetch,
		});

		const burst = 200;
		const begun = Date.now();
		const answers = await Promise.all(
			Array.from({ length: burst }, (_, i) =>
				resolver.resolve(`https://burst${i}.example/client.json`),
			),
		);
		expect(answers.every((answer) => answer === null)).toBe(true);
		expect(Date.now() - begun).toBeLessThan(1_000);
		// The running fetches and the queue for a slot, at most; the rest never reach the fetch.
		expect(fetches).toBeLessThanOrEqual(DEFAULT_CIMD_MAX_CONCURRENT_FETCHES * 5);
		expect(lookups).toBeLessThanOrEqual(CEILING);
		expect(warned).toHaveLength(burst);
		expect(warned.every((message) => message === "cimd_document_fetch_failed")).toBe(true);
	});
});

describe("the queue for a document fetch slot", () => {
	const neverAnswers = () => {
		const calls: string[] = [];
		const fetch = ((input: string | URL | Request) => {
			calls.push(String(input));
			return new Promise<Response>(() => undefined);
		}) as typeof globalThis.fetch;
		return { calls, fetch };
	};

	/** `promise`'s value, or `"pending"` when it has not settled within `ms`. */
	const within = <T,>(promise: Promise<T>, ms: number): Promise<T | "pending"> =>
		Promise.race([promise, new Promise<"pending">((r) => setTimeout(() => r("pending"), ms))]);

	it("is bounded at four times the slots: a request past it is not resolved, at once", async () => {
		const seam = neverAnswers();
		const warned: string[] = [];
		const resolver = createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy: createTestOutboundPolicy(),
			maxConcurrentFetches: 2,
			timeoutMs: 5_000,
			logger: logger(warned),
			fetch: seam.fetch,
		});
		const admitted = Array.from({ length: 2 + 8 }, (_, i) =>
			resolver.resolve(`https://q${i}.example/client.json`),
		);
		const begun = Date.now();
		const past = await within(
			Promise.all(
				Array.from({ length: 5 }, (_, i) => resolver.resolve(`https://over${i}.example/c.json`)),
			),
			1_000,
		);
		expect(past).toEqual([null, null, null, null, null]);
		expect(Date.now() - begun).toBeLessThan(500);
		expect(warned).toEqual(Array(5).fill("cimd_document_fetch_failed"));
		expect(seam.calls).toHaveLength(2);
		expect(admitted).toHaveLength(10);
	});

	it("is waited in no longer than the fetch deadline", async () => {
		const seam = neverAnswers();
		const resolver = createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy: createTestOutboundPolicy(),
			maxConcurrentFetches: 1,
			timeoutMs: 50,
			fetch: seam.fetch,
		});
		void resolver.resolve("https://running.example/client.json");
		const begun = Date.now();
		const waited = await within(resolver.resolve("https://waiting.example/client.json"), 2_000);
		expect(waited).toBeNull();
		const elapsed = Date.now() - begun;
		expect(elapsed).toBeGreaterThanOrEqual(40);
		expect(elapsed).toBeLessThan(1_000);
		expect(seam.calls).toEqual(["https://running.example/client.json"]);
	});

	it("is served in arrival order", async () => {
		const pending: Array<{ url: string; answer: (res: Response) => void }> = [];
		const resolver = createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy: createTestOutboundPolicy(),
			maxConcurrentFetches: 1,
			timeoutMs: 5_000,
			fetch: ((input: string | URL | Request) =>
				new Promise<Response>((answer) =>
					pending.push({ url: String(input), answer }),
				)) as typeof fetch,
		});
		const all = ["first", "a", "b", "c"].map((name) =>
			resolver.resolve(`https://${name}.example/client.json`),
		);
		for (let i = 0; i < 4; i += 1) {
			await new Promise((r) => setTimeout(r, 0));
			pending[i]?.answer(new Response(null, { status: 404 }));
		}
		await Promise.all(all);
		expect(pending.map((p) => p.url)).toEqual([
			"https://first.example/client.json",
			"https://a.example/client.json",
			"https://b.example/client.json",
			"https://c.example/client.json",
		]);
	});
});
