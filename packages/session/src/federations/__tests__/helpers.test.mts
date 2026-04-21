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

import { describe, expect, it } from "vitest";
import { fetchGithubPrimaryEmail } from "../helpers.mjs";

describe("fetchGithubPrimaryEmail", () => {
	const makeFetch = (response: unknown, status = 200) =>
		(async (_url: string, _init?: unknown) => ({
			status,
			ok: status >= 200 && status < 300,
			async json() {
				return response;
			},
		})) as unknown as typeof fetch;

	it("returns the primary verified email when present", async () => {
		const body = [
			{ email: "a@x.com", primary: false, verified: true },
			{ email: "primary@x.com", primary: true, verified: true },
			{ email: "b@x.com", primary: false, verified: false },
		];
		const email = await fetchGithubPrimaryEmail("token", makeFetch(body));
		expect(email).toEqual({ email: "primary@x.com", verified: true });
	});

	it("falls back to the first verified email when no primary exists", async () => {
		const body = [
			{ email: "unverified@x.com", primary: false, verified: false },
			{ email: "ok@x.com", primary: false, verified: true },
		];
		const email = await fetchGithubPrimaryEmail("token", makeFetch(body));
		expect(email).toEqual({ email: "ok@x.com", verified: true });
	});

	it("returns null when no verified email exists", async () => {
		const body = [
			{ email: "a@x.com", primary: true, verified: false },
			{ email: "b@x.com", primary: false, verified: false },
		];
		expect(await fetchGithubPrimaryEmail("token", makeFetch(body))).toBeNull();
	});

	it("returns null on 4xx/5xx without throwing", async () => {
		expect(await fetchGithubPrimaryEmail("token", makeFetch({ message: "nope" }, 401))).toBeNull();
		expect(await fetchGithubPrimaryEmail("token", makeFetch({}, 502))).toBeNull();
	});

	it("sends Authorization + User-Agent headers", async () => {
		let capturedInit: { headers?: Record<string, string> } | undefined;
		const fetchImpl = (async (_url: string, init?: unknown) => {
			capturedInit = init as { headers?: Record<string, string> };
			return {
				status: 200,
				ok: true,
				async json() {
					return [];
				},
			};
		}) as unknown as typeof fetch;
		await fetchGithubPrimaryEmail("token-123", fetchImpl);
		expect(capturedInit?.headers?.Authorization).toBe("Bearer token-123");
		expect(capturedInit?.headers?.["User-Agent"]).toMatch(/auth[.-]?provider/i);
		expect(capturedInit?.headers?.Accept).toBe("application/vnd.github+json");
	});

	it("passes an AbortSignal in the fetch init (timeout wiring)", async () => {
		let capturedInit: { signal?: unknown } | undefined;
		const fetchImpl = (async (_url: string, init?: unknown) => {
			capturedInit = init as { signal?: unknown };
			return {
				status: 200,
				ok: true,
				async json() {
					return [];
				},
			};
		}) as unknown as typeof fetch;
		await fetchGithubPrimaryEmail("any-token", fetchImpl);
		expect(capturedInit?.signal).toBeInstanceOf(AbortSignal);
	});

	it("returns null when the fetch is aborted (abort treated as unavailable)", async () => {
		const abortError = Object.assign(new Error("The operation was aborted."), {
			name: "AbortError",
		});
		const fetchImpl = (async () => {
			throw abortError;
		}) as unknown as typeof fetch;
		const result = await fetchGithubPrimaryEmail("token", fetchImpl);
		expect(result).toBeNull();
	});
});
