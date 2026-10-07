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
 * The public factory's fetches resolve under one pool for the process, sized
 * from `UV_THREADPOOL_SIZE` when the module loads. The system resolver is
 * replaced by one whose lookups stay outstanding until the test fails them,
 * so nothing is resolved or connected to.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const resolver = vi.hoisted(() => ({
	started: [] as string[],
	fail: [] as Array<() => void>,
}));

vi.mock("node:dns/promises", () => ({
	lookup: (hostname: string) =>
		new Promise((_resolve, reject) => {
			resolver.started.push(hostname);
			resolver.fail.push(() =>
				reject(Object.assign(new Error("not found"), { code: "ENOTFOUND" })),
			);
		}),
}));

/** The outbound fetch module as it loads with `UV_THREADPOOL_SIZE` = `size`. */
const loadWith = async (size: string | undefined) => {
	vi.stubEnv("UV_THREADPOOL_SIZE", size);
	vi.resetModules();
	return import("#/net/outbound-fetch.mjs");
};

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const reasonOf = async (promise: Promise<unknown>): Promise<string | undefined> => {
	try {
		await promise;
	} catch (err) {
		return (err as { reason?: string }).reason;
	}
	throw new Error("expected a rejection");
};

beforeEach(() => {
	resolver.started.length = 0;
	resolver.fail.length = 0;
	for (const variable of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]) {
		vi.stubEnv(variable, "");
	}
});

afterEach(() => {
	for (const fail of resolver.fail) fail();
	vi.unstubAllEnvs();
});

describe("the process-wide pool of lookups", () => {
	it("is shared by separately built fetches: two below the default threadpool of 4", async () => {
		const { createOutboundFetch } = await loadWith(undefined);
		const build = () => createOutboundFetch({ config: {}, source: "request", timeoutMs: 50 });
		const first = build();
		const second = build();
		const reasons = await Promise.all([
			reasonOf(first("https://a1.example/doc")),
			reasonOf(second("https://b1.example/doc")),
			reasonOf(first("https://a2.example/doc")),
			reasonOf(second("https://b2.example/doc")),
		]);
		expect(reasons).toEqual(["timeout", "timeout", "timeout", "timeout"]);
		expect(resolver.started).toEqual(["a1.example", "b1.example"]);

		// A third fetch, built later, finds the same two places taken.
		expect(await reasonOf(build()("https://c1.example/doc"))).toBe("timeout");
		expect(resolver.started).toHaveLength(2);

		// One lookup settles: one place comes free, for whichever fetch asks next.
		resolver.fail[0]?.();
		await flush();
		const next = reasonOf(second("https://b3.example/doc"));
		await flush();
		expect(resolver.started.at(-1)).toBe("b3.example");
		resolver.fail.at(-1)?.();
		expect(await next).toBe("resolution_failed");
	});

	it("is sized from UV_THREADPOOL_SIZE, read when the module loads", async () => {
		const { createOutboundFetch } = await loadWith("8");
		vi.stubEnv("UV_THREADPOOL_SIZE", "64");
		const first = createOutboundFetch({ config: {}, source: "request", timeoutMs: 50 });
		const second = createOutboundFetch({ config: {}, source: "request", timeoutMs: 50 });
		await Promise.all(
			Array.from({ length: 10 }, (_, i) =>
				reasonOf((i % 2 === 0 ? first : second)(`https://h${i}.example/doc`)),
			),
		);
		expect(resolver.started).toHaveLength(6);
	});

	it("keeps at least one place when the threadpool is that small", async () => {
		const { createOutboundFetch } = await loadWith("2");
		const fetch = createOutboundFetch({ config: {}, source: "request", timeoutMs: 50 });
		await Promise.all([
			reasonOf(fetch("https://one.example/doc")),
			reasonOf(fetch("https://two.example/doc")),
		]);
		expect(resolver.started).toEqual(["one.example"]);
	});
});
