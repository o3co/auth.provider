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

import { createSymmetricKeyStore } from "@o3co/auth-provider-core";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { broadcastBackchannelLogout } from "../broadcastBackchannel.mjs";

const keyStore = createSymmetricKeyStore("test-secret-32-chars-xxxxxxxxxx");

describe("broadcastBackchannelLogout", () => {
	it("POSTs logout_token to each RP's backchannelLogoutUri in parallel", async () => {
		const fetchMock = vi.fn(async () => ({ ok: true, status: 204, statusText: "No Content" }));
		await broadcastBackchannelLogout({
			rps: [
				{
					clientId: "rp1",
					backchannelLogoutUri: "https://rp1.example/bc",
					backchannelLogoutSessionRequired: true,
				},
				{
					clientId: "rp2",
					backchannelLogoutUri: "https://rp2.example/bc",
					backchannelLogoutSessionRequired: true,
				},
			],
			issuer: "iss",
			sub: "u",
			sid: "sid-1",
			keyStore,
			fetchImpl: fetchMock as unknown as typeof fetch,
		});
		expect(fetchMock).toHaveBeenCalledTimes(2);
		// Parallel dispatch — call order is non-deterministic; find rp1 by URL.
		const calls = fetchMock.mock.calls as unknown as [string, RequestInit][];
		const rp1Call = calls.find((c) => c[0] === "https://rp1.example/bc");
		expect(rp1Call).toBeDefined();
		const init = rp1Call?.[1];
		expect(init?.method).toBe("POST");
		const headers = init?.headers as Record<string, string>;
		expect(headers?.["Content-Type"]).toBe("application/x-www-form-urlencoded");
		const body = String(init?.body);
		expect(body).toMatch(/^logout_token=/);
		// Confirm rp2 was also called.
		expect(calls.find((c) => c[0] === "https://rp2.example/bc")).toBeDefined();
	});

	it("skips RPs without backchannelLogoutUri", async () => {
		const fetchMock = vi.fn(async () => ({ ok: true, status: 204, statusText: "" }));
		await broadcastBackchannelLogout({
			rps: [
				{ clientId: "rp1" }, // no URI
				{ clientId: "rp2", backchannelLogoutUri: "https://rp2.example/bc" },
			],
			issuer: "iss",
			sub: "u",
			sid: "sid-1",
			keyStore,
			fetchImpl: fetchMock as unknown as typeof fetch,
		});
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const skipCalls = fetchMock.mock.calls as unknown as [string, RequestInit][];
		expect(skipCalls[0]?.[0]).toBe("https://rp2.example/bc");
	});

	it("excludes sid from logout_token when backchannelLogoutSessionRequired: false", async () => {
		const fetchMock = vi.fn(async () => ({ ok: true, status: 204, statusText: "" }));
		await broadcastBackchannelLogout({
			rps: [
				{
					clientId: "rp1",
					backchannelLogoutUri: "https://rp.example/bc",
					backchannelLogoutSessionRequired: false,
				},
			],
			issuer: "iss",
			sub: "u",
			sid: "sid-1",
			keyStore,
			fetchImpl: fetchMock as unknown as typeof fetch,
		});
		const excludeCalls = fetchMock.mock.calls as unknown as [string, RequestInit][];
		const body = String(excludeCalls[0]?.[1]?.body);
		const params = new URLSearchParams(body);
		const logoutToken = params.get("logout_token");
		expect(logoutToken).not.toBeNull();
		// cast through unknown to avoid non-null assertion
		expect(
			(decodeJwt(logoutToken as unknown as string) as Record<string, unknown>).sid,
		).toBeUndefined();
	});

	it("includes sid by default (backchannelLogoutSessionRequired defaults to true)", async () => {
		const fetchMock = vi.fn(async () => ({ ok: true, status: 204, statusText: "" }));
		await broadcastBackchannelLogout({
			rps: [{ clientId: "rp1", backchannelLogoutUri: "https://rp.example/bc" }],
			issuer: "iss",
			sub: "u",
			sid: "sid-1",
			keyStore,
			fetchImpl: fetchMock as unknown as typeof fetch,
		});
		const includesCalls = fetchMock.mock.calls as unknown as [string, RequestInit][];
		const body = String(includesCalls[0]?.[1]?.body);
		const logoutToken = new URLSearchParams(body).get("logout_token");
		expect(logoutToken).not.toBeNull();
		expect((decodeJwt(logoutToken as unknown as string) as Record<string, unknown>).sid).toBe(
			"sid-1",
		);
	});

	it("times out slow RPs without delaying others (uses AbortController)", async () => {
		const slow = vi.fn((url: string, init?: RequestInit) => {
			void url;
			return new Promise<Response>((_resolve, reject) => {
				init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
			});
		});
		const fast = vi.fn(async (_url: string, _init?: RequestInit) => ({
			ok: true,
			status: 204,
			statusText: "",
		}));
		const fetchImpl = vi.fn((url: string, init?: RequestInit) => {
			return url === "https://slow.example/bc" ? slow(url, init) : fast(url, init);
		}) as unknown as typeof fetch;
		const logger = { warn: vi.fn() };
		const start = Date.now();
		await broadcastBackchannelLogout({
			rps: [
				{ clientId: "slow", backchannelLogoutUri: "https://slow.example/bc" },
				{ clientId: "fast", backchannelLogoutUri: "https://fast.example/bc" },
			],
			issuer: "iss",
			sub: "u",
			sid: "sid",
			keyStore,
			fetchImpl,
			timeoutMs: 200,
			logger,
		});
		expect(Date.now() - start).toBeLessThan(2_000);
		expect(fast).toHaveBeenCalled();
		expect(logger.warn).toHaveBeenCalled();
	}, 10_000);

	it("4xx/5xx RP responses are logged as warnings; broadcast resolves without throwing", async () => {
		const fetchMock = vi.fn(async () => ({
			ok: false,
			status: 500,
			statusText: "Internal Server Error",
		}));
		const logger = { warn: vi.fn() };
		await expect(
			broadcastBackchannelLogout({
				rps: [{ clientId: "rp1", backchannelLogoutUri: "https://rp.example/bc" }],
				issuer: "iss",
				sub: "u",
				sid: "sid",
				keyStore,
				fetchImpl: fetchMock as unknown as typeof fetch,
				logger,
			}),
		).resolves.toBeUndefined();
		expect(logger.warn).toHaveBeenCalled();
	});

	it("uses opts.logger over console.warn when provided", async () => {
		const fetchMock = vi.fn(async () => ({ ok: false, status: 500, statusText: "" }));
		const logger = { warn: vi.fn() };
		const consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			await broadcastBackchannelLogout({
				rps: [{ clientId: "rp1", backchannelLogoutUri: "https://rp.example/bc" }],
				issuer: "iss",
				sub: "u",
				sid: "sid",
				keyStore,
				fetchImpl: fetchMock as unknown as typeof fetch,
				logger,
			});
			expect(logger.warn).toHaveBeenCalled();
			expect(consoleWarnSpy).not.toHaveBeenCalled();
		} finally {
			consoleWarnSpy.mockRestore();
		}
	});

	it("never throws even if all RPs fail (best-effort guarantee)", async () => {
		const fetchMock = vi.fn(async () => {
			throw new Error("network partition");
		});
		const logger = { warn: vi.fn() };
		await expect(
			broadcastBackchannelLogout({
				rps: [
					{ clientId: "rp1", backchannelLogoutUri: "https://a/bc" },
					{ clientId: "rp2", backchannelLogoutUri: "https://b/bc" },
				],
				issuer: "iss",
				sub: "u",
				sid: "sid",
				keyStore,
				fetchImpl: fetchMock as unknown as typeof fetch,
				logger,
			}),
		).resolves.toBeUndefined();
		expect(logger.warn).toHaveBeenCalledTimes(2);
	});
});
