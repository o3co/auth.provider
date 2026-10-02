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
import {
	createOutboundFetchForTesting,
	type OutboundExchange,
	type OutboundTransport,
	withOutbound,
} from "@o3co/auth-provider-core/testing";
import { decodeJwt } from "jose";
import { describe, expect, it, vi } from "vitest";
import { createMockLogger } from "#/__tests__/_helpers/mockLogger.mjs";
import { expectBestEffortWarn, storeReplyError } from "#/__tests__/_helpers/projectedLog.mjs";
import { broadcastBackchannelLogout } from "#/logout/broadcastBackchannel.mjs";

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
		const logger = createMockLogger();
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
		const logger = createMockLogger();
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
		// The status, not the RP's own words for it.
		expectBestEffortWarn(
			logger,
			"logout_backchannel_rejected",
			{ clientId: "rp1", status: 500 },
			null,
		);
		expect(JSON.stringify(logger.warn.mock.calls)).not.toContain("Internal Server Error");
	});

	it("uses opts.logger over console.warn when provided", async () => {
		const fetchMock = vi.fn(async () => ({ ok: false, status: 500, statusText: "" }));
		const logger = createMockLogger();
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
		const logger = createMockLogger();
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
		for (const clientId of ["rp1", "rp2"]) {
			expectBestEffortWarn(
				logger,
				"logout_backchannel_failed",
				{ clientId, step: "post" },
				"Error",
			);
		}
	});

	it("logs a logout token it could not sign as the error's projection, and skips that RP's POST", async () => {
		// A key store backed by a store of its own can reject with that
		// store's error — the refused command's arguments and all.
		const failingKeyStore = Object.create(keyStore, {
			sign: { value: vi.fn().mockRejectedValue(storeReplyError()) },
		}) as typeof keyStore;
		const fetchMock = vi.fn(async () => ({ ok: true, status: 204, statusText: "" }));
		const logger = createMockLogger();
		await broadcastBackchannelLogout({
			rps: [{ clientId: "rp1", backchannelLogoutUri: "https://rp.example/bc" }],
			issuer: "iss",
			sub: "u",
			sid: "sid",
			keyStore: failingKeyStore,
			fetchImpl: fetchMock as unknown as typeof fetch,
			logger,
		});
		expect(fetchMock).not.toHaveBeenCalled();
		expectBestEffortWarn(logger, "logout_backchannel_failed", {
			clientId: "rp1",
			step: "logout_token",
		});
	});

	it("caps the client id it logs", async () => {
		const fetchMock = vi.fn(async () => ({ ok: false, status: 400, statusText: "" }));
		const logger = createMockLogger();
		await broadcastBackchannelLogout({
			rps: [{ clientId: "r".repeat(300), backchannelLogoutUri: "https://rp.example/bc" }],
			issuer: "iss",
			sub: "u",
			sid: "sid",
			keyStore,
			fetchImpl: fetchMock as unknown as typeof fetch,
			logger,
		});
		const [line] = logger.warn.mock.calls[0] ?? [];
		const logged = (line as { clientId?: unknown } | string).valueOf();
		expect(typeof logged).toBe("object");
		const { clientId } = logged as { clientId?: unknown };
		expect(typeof clientId).toBe("string");
		expect(String(clientId).length).toBeLessThanOrEqual(200);
	});
});

describe("broadcastBackchannelLogout — core's outbound fetch", () => {
	const answering =
		(status: number, body = "", headers: [string, string][] = []): OutboundTransport =>
		async () => ({
			status,
			statusText: "",
			headers,
			body: (async function* () {
				if (body.length > 0) yield new TextEncoder().encode(body);
			})(),
			close: () => {},
		});

	const broadcast = (
		rps: { clientId: string; backchannelLogoutUri: string }[],
		logger: ReturnType<typeof createMockLogger>,
		fetchImpl?: typeof fetch,
	) =>
		broadcastBackchannelLogout({
			rps,
			issuer: "iss",
			sub: "u",
			sid: "sid",
			keyStore,
			logger,
			...(fetchImpl === undefined ? {} : { fetchImpl }),
		});

	it.each([
		"https://127.0.0.1/bc",
		"https://[::1]/bc",
		"https://[::ffff:169.254.0.1]/bc",
		"https://u:p@127.0.0.1/bc",
		"http://127.0.0.1/bc",
	])(
		"with no fetchImpl, %s is refused as a destination and logout still completes",
		async (uri) => {
			const logger = createMockLogger();
			await expect(
				broadcast([{ clientId: "rp1", backchannelLogoutUri: uri }], logger),
			).resolves.toBe(undefined);
			expectBestEffortWarn(
				logger,
				"logout_backchannel_failed",
				{ clientId: "rp1", step: "destination" },
				"OutboundFetchError",
			);
		},
	);

	it("refuses one RP's destination and still posts to the next", async () => {
		const exchanges: OutboundExchange[] = [];
		const transport: OutboundTransport = async (exchange) => {
			exchanges.push(exchange);
			return answering(204)(exchange);
		};
		const lookup = vi.fn(async () => ["93.184.216.34"]);
		const logger = createMockLogger();
		await broadcast(
			[
				{ clientId: "refused", backchannelLogoutUri: "https://10.0.0.1/bc" },
				{ clientId: "reached", backchannelLogoutUri: "https://rp.example/bc" },
			],
			logger,
			createOutboundFetchForTesting({ source: "registration", lookup, transport }),
		);
		expectBestEffortWarn(
			logger,
			"logout_backchannel_failed",
			{ clientId: "refused", step: "destination" },
			"OutboundFetchError",
		);
		expect(exchanges).toHaveLength(1);
		expect(exchanges[0]?.url.href).toBe("https://rp.example/bc");
		expect(exchanges[0]?.addresses).toEqual(["93.184.216.34"]);
		expect(exchanges[0]?.method).toBe("POST");
	});

	it("refuses an http URI on a host that is not listed, before any lookup", async () => {
		const lookup = vi.fn(async () => ["93.184.216.34"]);
		const transport = vi.fn(answering(204));
		const logger = createMockLogger();
		await broadcast(
			[{ clientId: "rp1", backchannelLogoutUri: "http://rp.example/bc" }],
			logger,
			createOutboundFetchForTesting({ source: "registration", lookup, transport }),
		);
		expectBestEffortWarn(
			logger,
			"logout_backchannel_failed",
			{ clientId: "rp1", step: "destination" },
			"OutboundFetchError",
		);
		expect(lookup).not.toHaveBeenCalled();
		expect(transport).not.toHaveBeenCalled();
	});

	it("posts over http to a loopback host core.outbound.internalHosts lists", async () => {
		const transport = vi.fn(answering(204));
		const logger = createMockLogger();
		await broadcast(
			[{ clientId: "rp1", backchannelLogoutUri: "http://localhost:8080/bc" }],
			logger,
			createOutboundFetchForTesting({
				config: withOutbound({}, { internalHosts: ["localhost"] }),
				source: "registration",
				lookup: async () => ["127.0.0.1"],
				transport,
			}),
		);
		expect(transport).toHaveBeenCalledOnce();
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("treats a redirect as an unreachable destination and does not follow it", async () => {
		const transport = vi.fn(answering(307, "", [["location", "https://rp.example/elsewhere"]]));
		const logger = createMockLogger();
		await broadcast(
			[{ clientId: "rp1", backchannelLogoutUri: "https://rp.example/bc" }],
			logger,
			createOutboundFetchForTesting({
				source: "registration",
				lookup: async () => ["93.184.216.34"],
				transport,
			}),
		);
		expect(transport).toHaveBeenCalledOnce();
		expectBestEffortWarn(
			logger,
			"logout_backchannel_failed",
			{ clientId: "rp1", step: "destination" },
			"OutboundFetchError",
		);
	});

	it("treats an answer over the size cap as an unreachable destination", async () => {
		const logger = createMockLogger();
		await broadcast(
			[{ clientId: "rp1", backchannelLogoutUri: "https://rp.example/bc" }],
			logger,
			createOutboundFetchForTesting({
				config: withOutbound({}, { maxResponseBytes: 16 }),
				source: "registration",
				lookup: async () => ["93.184.216.34"],
				transport: answering(200, "x".repeat(64)),
			}),
		);
		expectBestEffortWarn(
			logger,
			"logout_backchannel_failed",
			{ clientId: "rp1", step: "destination" },
			"OutboundFetchError",
		);
	});

	it("keeps step post for an exchange that fails rather than is refused", async () => {
		const logger = createMockLogger();
		await broadcast(
			[{ clientId: "rp1", backchannelLogoutUri: "https://rp.example/bc" }],
			logger,
			createOutboundFetchForTesting({
				source: "registration",
				lookup: async () => {
					throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
				},
				transport: answering(204),
			}),
		);
		expectBestEffortWarn(
			logger,
			"logout_backchannel_failed",
			{ clientId: "rp1", step: "post" },
			"OutboundFetchError",
		);
	});
});
