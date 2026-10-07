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
 * `loginEntryContract` run over core's `createTestLoginEntry`, which keeps
 * every case, and the proof that its cases are not vacuous: each way an
 * entry can break the contract fails the case that names it.
 */

import type { LoginEntry } from "@o3co/auth-provider-core";
import { createTestLoginEntry } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { type LoginEntryContractInput, loginEntryContract } from "#/index.mjs";

const RULES = {
	url: "url is the login page it was built for",
	redirectTo: "urlFor adds redirect_to naming the target, once and whole",
	page: "urlFor keeps the page: its path and its own query, with nothing of the target read as either",
	fragment: "urlFor adds redirect_to to a page's query before its fragment, and keeps the fragment",
	refused: "a page whose own query already carries redirect_to is refused when the entry is built",
	frozen: "the login entry is frozen",
} as const;

/** The names of the cases the entries `build` makes fail. */
const failing = async (build: LoginEntryContractInput["build"]): Promise<string[]> => {
	const failed: string[] = [];
	for (const { name, run } of loginEntryContract({ build })) {
		try {
			await run();
		} catch {
			failed.push(name);
		}
	}
	return failed;
};

/** An entry for `url` whose `urlFor` is `urlFor`, frozen as a provider hands it. */
const entry = (url: string, urlFor: (target: string) => string): LoginEntry =>
	Object.freeze({ url, urlFor });

describe("loginEntryContract — the double", () => {
	const cases = loginEntryContract({ build: (url) => createTestLoginEntry(url) });

	it("names every rule", () => {
		expect(cases.map((c) => c.name)).toEqual([
			RULES.url,
			RULES.redirectTo,
			RULES.page,
			RULES.fragment,
			RULES.refused,
			RULES.frozen,
		]);
	});

	it.each(cases)("$name", async ({ run }) => {
		await run();
	});
});

describe("loginEntryContract — each way an entry can break it", () => {
	it("a url that is not the page it was built for", async () => {
		expect(await failing((url) => entry(`${url}/`, createTestLoginEntry(url).urlFor))).toContain(
			RULES.url,
		);
	});

	it("a target appended unencoded, so its own query and fragment read as the page's", async () => {
		expect(
			await failing((url) =>
				entry(url, (target) => `${url}${url.includes("?") ? "&" : "?"}redirect_to=${target}`),
			),
		).toEqual(expect.arrayContaining([RULES.redirectTo, RULES.page]));
	});

	it("a second ? after a page that already carries a query", async () => {
		expect(
			await failing((url) =>
				entry(url, (target) => `${url}?redirect_to=${encodeURIComponent(target)}`),
			),
		).toContain(RULES.page);
	});

	it("another parameter name, or none added", async () => {
		expect(
			await failing((url) =>
				entry(
					url,
					(target) =>
						`${url}${url.includes("?") ? "&" : "?"}return_to=${encodeURIComponent(target)}`,
				),
			),
		).toContain(RULES.redirectTo);
		expect(await failing((url) => entry(url, () => url))).toContain(RULES.redirectTo);
	});

	it("redirect_to appended after the page's fragment, where the page never reads it", async () => {
		expect(
			await failing((url) =>
				entry(
					url,
					(target) =>
						`${url}${url.includes("?") ? "&" : "?"}redirect_to=${encodeURIComponent(target)}`,
				),
			),
		).toContain(RULES.fragment);
	});

	it("an entry built for a page that already carries redirect_to", async () => {
		expect(
			await failing((url) => {
				const fragmentAt = url.indexOf("#");
				const page = fragmentAt === -1 ? url : url.slice(0, fragmentAt);
				const fragment = fragmentAt === -1 ? "" : url.slice(fragmentAt);
				const joiner = page.includes("?") ? "&" : "?";
				return entry(
					url,
					(target) => `${page}${joiner}redirect_to=${encodeURIComponent(target)}${fragment}`,
				);
			}),
		).toEqual([RULES.refused]);
	});

	it("an entry a reader could change under the others", async () => {
		expect(await failing((url) => ({ ...createTestLoginEntry(url) }))).toEqual([RULES.frozen]);
	});
});
