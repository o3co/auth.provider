/*
 * Copyright 2026 1o1 Co. Ltd.
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

import { describe, expect, it, vi } from "vitest";
import { postLogoutToken } from "#/logout/postLogoutToken.mjs";

describe("postLogoutToken", () => {
	it("POSTs the token as a form body and answers the status", async () => {
		const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
		const answer = await postLogoutToken("https://rp.example/bc", "tok.en", {
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(answer).toEqual({ ok: true, status: 204 });
		const call = (fetchImpl.mock.calls as unknown as [string, RequestInit][])[0];
		if (call === undefined) throw new Error("no POST was made");
		const [url, init] = call;
		expect(url).toBe("https://rp.example/bc");
		expect(init.method).toBe("POST");
		expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
			"application/x-www-form-urlencoded",
		);
		expect(new URLSearchParams(String(init.body)).get("logout_token")).toBe("tok.en");
	});

	it("answers a non-2xx status without throwing", async () => {
		const fetchImpl = vi.fn(async () => new Response("no", { status: 400 }));
		await expect(
			postLogoutToken("https://rp.example/bc", "t", {
				fetchImpl: fetchImpl as unknown as typeof fetch,
			}),
		).resolves.toEqual({ ok: false, status: 400 });
	});

	it("aborts a request that outlives its deadline, and rejects", async () => {
		const fetchImpl = vi.fn(
			(_url: string, init?: RequestInit) =>
				new Promise<Response>((_resolve, reject) => {
					init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
				}),
		);
		const start = Date.now();
		await expect(
			postLogoutToken("https://slow.example/bc", "t", {
				fetchImpl: fetchImpl as unknown as typeof fetch,
				timeoutMs: 50,
			}),
		).rejects.toThrow("aborted");
		expect(Date.now() - start).toBeLessThan(2_000);
	});

	it("passes a rejection of the fetch through unchanged", async () => {
		const refusal = new Error("refused");
		const fetchImpl = vi.fn(async () => {
			throw refusal;
		});
		await expect(
			postLogoutToken("https://rp.example/bc", "t", {
				fetchImpl: fetchImpl as unknown as typeof fetch,
			}),
		).rejects.toBe(refusal);
	});
});
