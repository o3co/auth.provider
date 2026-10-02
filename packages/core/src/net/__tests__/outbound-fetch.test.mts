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
 * The outbound fetch's rules, through its test seams: a stubbed resolver and
 * a transport that records what it was asked to connect to and answers as
 * told. The real sockets are `outbound-transport.test.mts`'s.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { loggableError } from "#/logging/loggableError.mjs";
import { createOutboundFetch, isOutboundRefusal } from "#/net/outbound-fetch.mjs";
import type { OutboundExchange, OutboundTransport } from "#/net/outbound-transport.mjs";
import {
	createOutboundFetchForTesting,
	OutboundFetchError,
	type OutboundSectionForTests,
	withOutbound,
} from "#/testing/outboundFetch.mjs";

const PUBLIC_V4 = "93.184.216.34";

interface Lookup {
	readonly calls: string[];
	readonly lookup: (hostname: string) => Promise<readonly string[]>;
}

/** A resolver that answers `answers` (by host, or one answer for every host) and records each question. */
const resolver = (
	answers: readonly string[] | Readonly<Record<string, readonly string[]>> = [PUBLIC_V4],
): Lookup => {
	const calls: string[] = [];
	return {
		calls,
		lookup: async (hostname) => {
			calls.push(hostname);
			if (Array.isArray(answers)) return answers;
			const answer = (answers as Readonly<Record<string, readonly string[]>>)[hostname];
			if (answer === undefined) throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
			return answer;
		},
	};
};

interface AnswerSpec {
	readonly status?: number;
	readonly statusText?: string;
	readonly headers?: readonly (readonly [string, string])[];
	readonly chunks?: readonly (string | Uint8Array)[];
	/** After the chunks, the body never ends. */
	readonly stall?: boolean;
}

interface Recorder {
	readonly exchanges: OutboundExchange[];
	readonly transport: OutboundTransport;
	/** How many answers were closed. */
	closed(): number;
	/** How many body chunks were handed out. */
	read(): number;
}

/** A transport that answers every exchange with `spec`, recording the exchange. */
const answering = (spec: AnswerSpec = {}): Recorder => {
	const exchanges: OutboundExchange[] = [];
	let closed = 0;
	let read = 0;
	return {
		exchanges,
		closed: () => closed,
		read: () => read,
		transport: async (exchange) => {
			exchanges.push(exchange);
			async function* body(): AsyncGenerator<Uint8Array> {
				for (const chunk of spec.chunks ?? []) {
					read += 1;
					yield typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk;
				}
				if (spec.stall) await new Promise(() => undefined);
			}
			return {
				status: spec.status ?? 200,
				statusText: spec.statusText ?? "",
				headers: spec.headers ?? [],
				body: body(),
				close: () => {
					closed += 1;
				},
			};
		},
	};
};

/** A transport that never answers. */
const silent: OutboundTransport = () => new Promise(() => undefined);

const config = (outbound: OutboundSectionForTests) => withOutbound({}, outbound);

const outboundFetch = (
	options: {
		readonly outbound?: OutboundSectionForTests;
		readonly source?: "registration" | "request";
		readonly lookup?: Lookup;
		readonly transport?: OutboundTransport | Recorder;
		readonly timeoutMs?: number;
		readonly maxResponseBytes?: number;
	} = {},
) => {
	const transport = options.transport ?? answering();
	return createOutboundFetchForTesting({
		...(options.outbound !== undefined ? { config: config(options.outbound) } : {}),
		source: options.source ?? "registration",
		lookup: (options.lookup ?? resolver()).lookup,
		transport: typeof transport === "function" ? transport : transport.transport,
		...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
		...(options.maxResponseBytes !== undefined
			? { maxResponseBytes: options.maxResponseBytes }
			: {}),
	});
};

/** The error `promise` rejects with; fails the test when it resolves. */
const rejection = async (promise: Promise<unknown>): Promise<unknown> => {
	try {
		await promise;
	} catch (err) {
		return err;
	}
	throw new Error("expected a rejection");
};

/** The policy refusal `promise` rejects with. */
const refusal = async (promise: Promise<unknown>, reason: string): Promise<OutboundFetchError> => {
	const err = await rejection(promise);
	expect(err).toBeInstanceOf(OutboundFetchError);
	expect((err as OutboundFetchError).reason).toBe(reason);
	expect(isOutboundRefusal(err)).toBe(true);
	return err as OutboundFetchError;
};

/** A failure that is not a refusal: the network, the resolver or the deadline. */
const failure = async (promise: Promise<unknown>, reason: string): Promise<OutboundFetchError> => {
	const err = await rejection(promise);
	expect(err).toBeInstanceOf(OutboundFetchError);
	expect((err as OutboundFetchError).reason).toBe(reason);
	expect(isOutboundRefusal(err)).toBe(false);
	return err as OutboundFetchError;
};

describe("the URL: scheme, credentials and port", () => {
	it("refuses plain http to a host that is not a listed loopback host, before any lookup", async () => {
		const lookup = resolver();
		const fetch = outboundFetch({ lookup, outbound: { internalHosts: ["rp.example"] } });
		await refusal(fetch("http://rp.example/"), "scheme_not_allowed");
		await refusal(fetch("http://localhost/"), "scheme_not_allowed");
		expect(lookup.calls).toEqual([]);
	});

	it("refuses every scheme but https and http", async () => {
		const fetch = outboundFetch();
		for (const url of [
			"ftp://rp.example/",
			"file:///etc/hosts",
			"data:text/plain,x",
			"ws://rp.example/",
		]) {
			await refusal(fetch(url), "scheme_not_allowed");
		}
	});

	it("admits plain http to a loopback host internalHosts lists, for a URL from a registration only", async () => {
		const recorder = answering();
		const outbound = { internalHosts: ["localhost"] };
		const lookup = resolver(["127.0.0.1"]);
		const res = await outboundFetch({ outbound, lookup, transport: recorder })(
			"http://localhost:8080/bc",
		);
		expect(res.status).toBe(200);
		expect(recorder.exchanges.map((e) => e.addresses)).toEqual([["127.0.0.1"]]);

		await refusal(
			outboundFetch({ outbound, source: "request", lookup: resolver(["127.0.0.1"]) })(
				"http://localhost:8080/bc",
			),
			"scheme_not_allowed",
		);
	});

	it("refuses plain http to a listed loopback name that resolves off the machine", async () => {
		const fetch = outboundFetch({
			outbound: { internalHosts: ["localhost"] },
			lookup: resolver(["10.0.0.9"]),
		});
		await refusal(fetch("http://localhost/"), "scheme_not_allowed");
	});

	it("refuses a URL it cannot parse, or whose host has an empty label", async () => {
		const fetch = outboundFetch();
		await refusal(fetch("not a url"), "url_unparseable");
		await refusal(fetch("https://rp.example../"), "url_unparseable");
	});

	it("refuses credentials in the URL, before any lookup", async () => {
		const lookup = resolver();
		const fetch = outboundFetch({ lookup });
		await refusal(fetch("https://u:p@rp.example/"), "userinfo_present");
		await refusal(fetch("https://u@rp.example/"), "userinfo_present");
		expect(lookup.calls).toEqual([]);
	});

	it("refuses a port on the Fetch standard's bad-port list, before any lookup", async () => {
		const lookup = resolver();
		const fetch = outboundFetch({ lookup });
		for (const port of [0, 636, 25, 22, 6667, 10080]) {
			await refusal(fetch(`https://rp.example:${port}/`), "port_not_allowed");
		}
		expect(lookup.calls).toEqual([]);
		expect((await fetch("https://rp.example:8443/")).status).toBe(200);
	});
});

describe("IP-literal hosts", () => {
	it("refuses a special-use IPv4 literal in every spelling, with no lookup and no connection", async () => {
		const lookup = resolver();
		const recorder = answering();
		const fetch = outboundFetch({ lookup, transport: recorder });
		for (const url of [
			"https://127.0.0.1/",
			"https://10.0.0.1/",
			"https://169.254.169.254/",
			"https://0.0.0.0/",
			"https://2130706433/",
			"https://0x7f000001/",
			"https://127.1/",
		]) {
			await refusal(fetch(url), "special_use_address");
		}
		expect(lookup.calls).toEqual([]);
		expect(recorder.exchanges).toEqual([]);
	});

	it("refuses a special-use IPv6 literal, IPv4-mapped forms by their IPv4 half", async () => {
		const recorder = answering();
		const fetch = outboundFetch({ transport: recorder });
		for (const url of [
			"https://[::1]/",
			"https://[fe80::1]/",
			"https://[fc00::1]/",
			"https://[fec0::1]/",
			"https://[64:ff9b:1::a00:1]/",
			"https://[::ffff:169.254.169.254]/",
			"https://[::ffff:a9fe:a9fe]/",
			"https://[::ffff:127.0.0.1]/",
		]) {
			await refusal(fetch(url), "special_use_address");
		}
		expect(recorder.exchanges).toEqual([]);
	});

	it("connects to a public literal as written, with no lookup and no server name", async () => {
		const lookup = resolver();
		const recorder = answering();
		const fetch = outboundFetch({ lookup, transport: recorder });
		await fetch(`https://${PUBLIC_V4}/jwks`);
		await fetch("https://[2606:4700:4700::1111]/jwks");
		expect(lookup.calls).toEqual([]);
		expect(recorder.exchanges.map((e) => [e.addresses, e.servername])).toEqual([
			[[PUBLIC_V4], undefined],
			[["2606:4700:4700::1111"], undefined],
		]);
	});
});

describe("resolved addresses", () => {
	it("refuses a name that resolves to a special-use address, without connecting", async () => {
		for (const answer of [
			["10.0.0.5"],
			["::ffff:10.0.0.5"],
			["fec0::1"],
			["64:ff9b:1::a00:1"],
			["fe80::1%eth0"],
		]) {
			const recorder = answering();
			await refusal(
				outboundFetch({ lookup: resolver(answer), transport: recorder })("https://rp.example/"),
				"special_use_address",
			);
			expect(recorder.exchanges).toEqual([]);
		}
	});

	it("refuses a mixed answer: one special-use address among public ones is enough", async () => {
		const recorder = answering();
		await refusal(
			outboundFetch({ lookup: resolver([PUBLIC_V4, "10.0.0.5"]), transport: recorder })(
				"https://rp.example/",
			),
			"special_use_address",
		);
		expect(recorder.exchanges).toEqual([]);
	});

	it("reports a lookup that fails, answers nothing or answers a non-address as a failure, not a refusal", async () => {
		await failure(
			outboundFetch({ lookup: resolver({}) })("https://rp.example/"),
			"resolution_failed",
		);
		await failure(
			outboundFetch({ lookup: resolver([]) })("https://rp.example/"),
			"resolution_failed",
		);
		await failure(
			outboundFetch({ lookup: resolver(["rp.example"]) })("https://rp.example/"),
			"resolution_failed",
		);
	});

	it("resolves once, and hands the transport exactly the addresses it checked and the name for SNI", async () => {
		const lookup = resolver(["2606:4700:4700::1111", PUBLIC_V4]);
		const recorder = answering();
		await outboundFetch({ lookup, transport: recorder })("https://RP.example./x?y=1");
		expect(lookup.calls).toEqual(["rp.example."]);
		expect(recorder.exchanges).toHaveLength(1);
		const [exchange] = recorder.exchanges;
		expect(exchange?.addresses).toEqual(["2606:4700:4700::1111", PUBLIC_V4]);
		expect(exchange?.servername).toBe("rp.example");
		expect(exchange?.url.href).toBe("https://rp.example./x?y=1");
	});
});

describe("internalHosts", () => {
	it("admits a listed host at a special-use address for a URL from a registration", async () => {
		const recorder = answering();
		const res = await outboundFetch({
			outbound: { internalHosts: [".corp.example"] },
			lookup: resolver(["10.0.0.5"]),
			transport: recorder,
		})("https://keys.corp.example/jwks");
		expect(res.status).toBe(200);
		expect(recorder.exchanges.map((e) => e.addresses)).toEqual([["10.0.0.5"]]);
	});

	it("never applies to a URL from a request", async () => {
		const recorder = answering();
		await refusal(
			outboundFetch({
				outbound: { internalHosts: [".corp.example", "10.0.0.5"] },
				source: "request",
				lookup: resolver(["10.0.0.5"]),
				transport: recorder,
			})("https://keys.corp.example/jwks"),
			"special_use_address",
		);
		await refusal(
			outboundFetch({
				outbound: { internalHosts: ["10.0.0.5"] },
				source: "request",
				transport: recorder,
			})("https://10.0.0.5/jwks"),
			"special_use_address",
		);
		expect(recorder.exchanges).toEqual([]);
	});

	it("admits a listed special-use literal for a URL from a registration", async () => {
		const recorder = answering();
		await outboundFetch({ outbound: { internalHosts: ["10.0.0.5"] }, transport: recorder })(
			"https://10.0.0.5/jwks",
		);
		expect(recorder.exchanges.map((e) => e.addresses)).toEqual([["10.0.0.5"]]);
	});
});

describe("host lists", () => {
	it("refuses a host deniedHosts lists, over allowedHosts and internalHosts", async () => {
		const lookup = resolver();
		const fetch = outboundFetch({
			lookup,
			outbound: {
				allowedHosts: ["rp.example"],
				internalHosts: ["rp.example"],
				deniedHosts: ["rp.example"],
			},
		});
		await refusal(fetch("https://rp.example/"), "host_not_allowed");
		expect(lookup.calls).toEqual([]);
	});

	it("matches a suffix entry for the domain and its subdomains, ignoring case and a trailing dot", async () => {
		const fetch = outboundFetch({ outbound: { deniedHosts: [".blocked.example", "RP.example"] } });
		for (const url of [
			"https://blocked.example/",
			"https://a.b.blocked.example/",
			"https://A.Blocked.Example/",
			"https://rp.example./",
			"https://RP.EXAMPLE/",
		]) {
			await refusal(fetch(url), "host_not_allowed");
		}
		expect((await fetch("https://notblocked.example/")).status).toBe(200);
	});

	it("matches an IDNA entry against the punycode host, and an IPv4 entry against its mapped literal", async () => {
		const fetch = outboundFetch({
			outbound: { deniedHosts: ["bücher.example", "10.0.0.5.", PUBLIC_V4] },
		});
		await refusal(fetch("https://xn--bcher-kva.example/"), "host_not_allowed");
		await refusal(fetch("https://[::ffff:10.0.0.5]/"), "host_not_allowed");
		await refusal(fetch(`https://[::ffff:${PUBLIC_V4}]/`), "host_not_allowed");
	});

	it("refuses a host a non-empty allowedHosts does not list", async () => {
		const fetch = outboundFetch({ outbound: { allowedHosts: [".partner.example"] } });
		await refusal(fetch("https://rp.example/"), "host_not_allowed");
		expect((await fetch("https://idp.partner.example/")).status).toBe(200);
	});
});

describe("the answer", () => {
	it("refuses every redirect without following it", async () => {
		for (const status of [300, 301, 302, 303, 307, 308]) {
			const lookup = resolver();
			const recorder = answering({
				status,
				headers: [["location", "http://10.0.0.1/"]],
				chunks: ["moved"],
			});
			await refusal(
				outboundFetch({ lookup, transport: recorder })("https://rp.example/"),
				"redirect_refused",
			);
			expect(lookup.calls).toHaveLength(1);
			expect(recorder.exchanges).toHaveLength(1);
			expect(recorder.closed()).toBe(1);
		}
	});

	it("passes a 304 with a null body, whatever Content-Length it declares", async () => {
		const recorder = answering({
			status: 304,
			headers: [
				["etag", '"v2"'],
				["content-length", "10485760"],
			],
		});
		const res = await outboundFetch({ transport: recorder, maxResponseBytes: 16 })(
			"https://rp.example/",
		);
		expect(res.status).toBe(304);
		expect(res.body).toBeNull();
		expect(res.headers.get("etag")).toBe('"v2"');
		expect(recorder.closed()).toBe(1);
	});

	it("answers a status that is not 2xx with a null body, without reading or waiting for it", async () => {
		for (const status of [404, 503, 400]) {
			const recorder = answering({
				status,
				headers: [["content-length", "10485760"]],
				chunks: ["x".repeat(64)],
				stall: true,
			});
			const res = await outboundFetch({
				transport: recorder,
				maxResponseBytes: 16,
				timeoutMs: 200,
			})("https://rp.example/");
			expect(res.status).toBe(status);
			expect(res.body).toBeNull();
			expect(recorder.read()).toBe(0);
			expect(recorder.closed()).toBe(1);
		}
	});

	it("answers 204 and 205 with a null body", async () => {
		for (const status of [204, 205]) {
			const res = await outboundFetch({ transport: answering({ status }) })("https://rp.example/");
			expect(res.status).toBe(status);
			expect(res.body).toBeNull();
		}
	});

	it("returns a 2xx body read in full, with its status and headers", async () => {
		const recorder = answering({
			status: 200,
			statusText: "OK",
			headers: [["content-type", "application/json"]],
			chunks: ['{"keys":', "[]}"],
		});
		const res = await outboundFetch({ transport: recorder })("https://rp.example/jwks");
		expect(res.status).toBe(200);
		expect(res.statusText).toBe("OK");
		expect(res.headers.get("content-type")).toBe("application/json");
		expect(await res.json()).toEqual({ keys: [] });
		expect(recorder.closed()).toBe(1);
	});

	it("refuses a declared Content-Length over the cap before reading the body", async () => {
		const recorder = answering({ headers: [["content-length", "17"]], chunks: ["x".repeat(17)] });
		await refusal(
			outboundFetch({ transport: recorder, maxResponseBytes: 16 })("https://rp.example/"),
			"response_too_large",
		);
		expect(recorder.read()).toBe(0);
		expect(recorder.closed()).toBe(1);
	});

	it("refuses a body that grows past the cap while it is read, and admits exactly the cap", async () => {
		const over = answering({ chunks: ["x".repeat(10), "x".repeat(7), "x".repeat(1000)] });
		await refusal(
			outboundFetch({ transport: over, maxResponseBytes: 16 })("https://rp.example/"),
			"response_too_large",
		);
		expect(over.read()).toBe(2);
		expect(over.closed()).toBe(1);

		const exact = answering({ chunks: ["x".repeat(10), "x".repeat(6)] });
		const res = await outboundFetch({ transport: exact, maxResponseBytes: 16 })(
			"https://rp.example/",
		);
		expect((await res.text()).length).toBe(16);
	});

	it("caps at core.outbound.maxResponseBytes, 64 KiB by default", async () => {
		const big = answering({ chunks: ["x".repeat(65537)] });
		await refusal(outboundFetch({ transport: big })("https://rp.example/"), "response_too_large");
		const configured = answering({ chunks: ["x".repeat(33)] });
		await refusal(
			outboundFetch({ transport: configured, outbound: { maxResponseBytes: 32 } })(
				"https://rp.example/",
			),
			"response_too_large",
		);
		const fits = answering({ chunks: ["x".repeat(65536)] });
		expect((await outboundFetch({ transport: fits })("https://rp.example/")).status).toBe(200);
	});

	it("asks for the identity encoding, and refuses a 2xx in any other", async () => {
		const recorder = answering({
			headers: [["content-encoding", "gzip"]],
			chunks: ["\u001f\u008b"],
		});
		await refusal(
			outboundFetch({ transport: recorder })("https://rp.example/", {
				headers: { "Accept-Encoding": "gzip, br" },
			}),
			"unsupported_encoding",
		);
		expect(recorder.exchanges[0]?.headers["accept-encoding"]).toBe("identity");
		expect(recorder.read()).toBe(0);

		const identity = answering({ headers: [["content-encoding", "Identity"]], chunks: ["ok"] });
		expect(await (await outboundFetch({ transport: identity })("https://rp.example/")).text()).toBe(
			"ok",
		);
	});
});

describe("the deadline and the caller's signal", () => {
	it("fails with timeout when nothing answers in time", async () => {
		const started = Date.now();
		await failure(
			outboundFetch({ transport: silent, timeoutMs: 50 })("https://rp.example/"),
			"timeout",
		);
		expect(Date.now() - started).toBeLessThan(2000);
	});

	it("covers the lookup: a resolver that never answers fails with timeout", async () => {
		const lookup: Lookup = { calls: [], lookup: () => new Promise(() => undefined) };
		await failure(outboundFetch({ lookup, timeoutMs: 50 })("https://rp.example/"), "timeout");
	});

	it("covers the body: a 2xx body that stalls fails with timeout, and the answer is closed", async () => {
		const recorder = answering({ chunks: ["x"], stall: true });
		await failure(
			outboundFetch({ transport: recorder, timeoutMs: 50 })("https://rp.example/"),
			"timeout",
		);
		expect(recorder.closed()).toBe(1);
	});

	it("takes the shorter of core.outbound.timeoutMs and a per-use timeoutMs", async () => {
		await failure(
			outboundFetch({ transport: silent, outbound: { timeoutMs: 50 } })("https://rp.example/"),
			"timeout",
		);
		await failure(
			outboundFetch({ transport: silent, outbound: { timeoutMs: 60_000 }, timeoutMs: 50 })(
				"https://rp.example/",
			),
			"timeout",
		);
		// The operator's value is a ceiling a caller cannot raise.
		const started = Date.now();
		await failure(
			outboundFetch({ transport: silent, outbound: { timeoutMs: 50 }, timeoutMs: 60_000 })(
				"https://rp.example/",
			),
			"timeout",
		);
		expect(Date.now() - started).toBeLessThan(5_000);
	});

	it("caps at the smaller of core.outbound.maxResponseBytes and a per-use maxResponseBytes", async () => {
		await refusal(
			outboundFetch({
				transport: answering({ chunks: ["x".repeat(17)] }),
				outbound: { maxResponseBytes: 16 },
				maxResponseBytes: 1_000,
			})("https://rp.example/"),
			"response_too_large",
		);
		await refusal(
			outboundFetch({
				transport: answering({ chunks: ["x".repeat(17)] }),
				outbound: { maxResponseBytes: 1_000 },
				maxResponseBytes: 16,
			})("https://rp.example/"),
			"response_too_large",
		);
	});

	it("rejects with the caller's own reason when the caller aborts", async () => {
		const controller = new AbortController();
		const reason = new Error("caller gave up");
		const pending = outboundFetch({ transport: silent })("https://rp.example/", {
			signal: controller.signal,
		});
		controller.abort(reason);
		expect(await rejection(pending)).toBe(reason);
	});

	it("keeps a TimeoutError from the caller's signal as it is", async () => {
		const err = await rejection(
			outboundFetch({ transport: silent })("https://rp.example/", {
				signal: AbortSignal.timeout(20),
			}),
		);
		expect((err as Error).name).toBe("TimeoutError");
		expect(err).not.toBeInstanceOf(OutboundFetchError);
	});

	it("observes every pending read when the caller aborts between the answer and its body", async () => {
		const controller = new AbortController();
		const reason = new Error("caller gave up");
		const transport: OutboundTransport = async () => ({
			status: 200,
			statusText: "",
			// Read just before the body: the caller aborts at exactly that point.
			get headers() {
				controller.abort(reason);
				return [];
			},
			body: {
				[Symbol.asyncIterator]: () => ({
					next: () => Promise.reject(new Error("body destroyed")),
				}),
			},
			close: () => undefined,
		});
		const pending = outboundFetch({ transport })("https://rp.example/", {
			signal: controller.signal,
		});
		expect(await rejection(pending)).toBe(reason);
		// An unobserved rejection would surface here as an unhandled error.
		await new Promise((resolve) => setTimeout(resolve, 20));
	});

	it("does nothing for a signal already aborted", async () => {
		const lookup = resolver();
		const reason = new Error("already");
		expect(
			await rejection(
				outboundFetch({ lookup })("https://rp.example/", { signal: AbortSignal.abort(reason) }),
			),
		).toBe(reason);
		expect(lookup.calls).toEqual([]);
	});
});

describe("the request it sends", () => {
	it("sends a POST body with its length and the content type fetch would give it", async () => {
		const recorder = answering();
		await outboundFetch({ transport: recorder })("https://rp.example/bc", {
			method: "post",
			body: new URLSearchParams({ logout_token: "t" }),
		});
		const [exchange] = recorder.exchanges;
		expect(exchange?.method).toBe("POST");
		expect(new TextDecoder().decode(exchange?.body)).toBe("logout_token=t");
		expect(exchange?.headers["content-type"]).toBe(
			"application/x-www-form-urlencoded;charset=UTF-8",
		);
		expect(exchange?.headers["content-length"]).toBe("14");
	});

	it("keeps the caller's headers, a Headers object included, but not the ones the transport owns", async () => {
		const recorder = answering();
		const headers = new Headers({
			accept: "application/json",
			"content-type": "application/jwt",
			host: "elsewhere.example",
			connection: "upgrade",
		});
		await outboundFetch({ transport: recorder })("https://rp.example/", {
			method: "POST",
			headers,
			body: "abc",
		});
		const sent = recorder.exchanges[0]?.headers;
		expect(sent?.accept).toBe("application/json");
		expect(sent?.["content-type"]).toBe("application/jwt");
		expect(sent?.host).toBeUndefined();
		expect(sent?.connection).toBeUndefined();
		expect(sent?.["content-length"]).toBe("3");
	});

	it("takes a URL object as well as a string", async () => {
		const recorder = answering();
		await outboundFetch({ transport: recorder })(new URL("https://rp.example/a"));
		expect(recorder.exchanges[0]?.url.href).toBe("https://rp.example/a");
	});

	it("refuses with a TypeError what it does not support: a Request, another method, another body", async () => {
		const fetch = outboundFetch();
		await expect(fetch(new Request("https://rp.example/"))).rejects.toBeInstanceOf(TypeError);
		await expect(fetch("https://rp.example/", { method: "PUT" })).rejects.toBeInstanceOf(TypeError);
		await expect(
			fetch("https://rp.example/", { method: "POST", body: new Blob(["x"]) }),
		).rejects.toBeInstanceOf(TypeError);
		await expect(fetch("https://rp.example/", { body: "x" })).rejects.toBeInstanceOf(TypeError);
	});
});

describe("building the fetch", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
	});

	it("refuses a malformed core.outbound, naming the key, rather than reading it as the defaults", () => {
		expect(() =>
			createOutboundFetch({
				config: { core: { outbound: { deniedHosts: ["https://rp.example/"] } } },
				source: "registration",
			}),
		).toThrow(/core\.outbound\.deniedHosts\.0/);
		expect(() =>
			createOutboundFetch({ config: { core: { outbound: { timeout: 5 } } }, source: "request" }),
		).toThrow(/core\.outbound.*timeout/);
		expect(() =>
			createOutboundFetch({ config: { core: { outbound: null } }, source: "request" }),
		).toThrow(/core\.outbound/);
	});

	it("reads an absent section, or no configuration at all, as the defaults", () => {
		expect(() => createOutboundFetch({ source: "request" })).not.toThrow();
		expect(() => createOutboundFetch({ config: { core: {} }, source: "request" })).not.toThrow();
	});

	it("requires the URL's source", () => {
		// @ts-expect-error: `source` is required
		expect(() => createOutboundFetch({})).toThrow(TypeError);
		expect(() => createOutboundFetch({ source: "client" as unknown as "request" })).toThrow(
			TypeError,
		);
	});

	it("refuses a per-use timeoutMs or maxResponseBytes that is not a positive whole number", () => {
		expect(() => createOutboundFetch({ source: "request", timeoutMs: 2_147_483_648 })).toThrow(
			TypeError,
		);
		expect(() =>
			createOutboundFetch({ source: "request", timeoutMs: 2_147_483_647 }),
		).not.toThrow();
		for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
			expect(() => createOutboundFetch({ source: "request", timeoutMs: bad })).toThrow(TypeError);
			expect(() => createOutboundFetch({ source: "request", maxResponseBytes: bad })).toThrow(
				TypeError,
			);
		}
	});

	it('refuses to build while an environment proxy is configured, unless egress = "direct"', () => {
		for (const variable of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]) {
			vi.stubEnv(variable, "http://proxy.example:3128");
			expect(() => createOutboundFetch({ source: "registration" }), variable).toThrow(
				/core\.outbound\.egress/,
			);
			expect(() =>
				createOutboundFetch({ config: config({ egress: "direct" }), source: "registration" }),
			).not.toThrow();
			vi.unstubAllEnvs();
		}
		vi.stubEnv("HTTPS_PROXY", "");
		expect(() => createOutboundFetch({ source: "registration" })).not.toThrow();
	});

	it("does not consult the global fetch dispatcher, which it never connects through", () => {
		const key = Symbol.for("undici.globalDispatcher.1");
		const holder = globalThis as unknown as Record<symbol, unknown>;
		const before = holder[key];
		holder[key] = { dispatch: () => false };
		try {
			expect(() => createOutboundFetch({ source: "registration" })).not.toThrow();
		} finally {
			holder[key] = before;
		}
	});
});

describe("what a refusal carries", () => {
	it("is a code loggableError keeps as reason, in a message with none of the peer's bytes", async () => {
		const err = await refusal(
			outboundFetch({
				transport: answering({
					status: 302,
					statusText: "PEER-STATUS-TEXT",
					headers: [["location", "https://peer-location.example/"]],
					chunks: ["PEER-BODY"],
				}),
			})("https://rp.example/"),
			"redirect_refused",
		);
		const logged = loggableError(err);
		expect(logged.reason).toBe("redirect_refused");
		const text = JSON.stringify(logged);
		expect(text).not.toContain("PEER");
		expect(text).not.toContain("peer-location");
		expect(err.message).toContain("rp.example");
	});

	it("is told apart from everything else by isOutboundRefusal alone", () => {
		expect(isOutboundRefusal(new Error("x"))).toBe(false);
		expect(isOutboundRefusal(new TypeError("x"))).toBe(false);
		expect(isOutboundRefusal(undefined)).toBe(false);
		expect(isOutboundRefusal({ reason: "host_not_allowed" })).toBe(false);
	});
});
