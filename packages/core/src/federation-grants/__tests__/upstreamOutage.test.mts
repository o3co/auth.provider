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
 * Whether a failed upstream call is an outage — the upstream not reached, not
 * in time, or answering with a 5xx — rather than the upstream's refusal. Read
 * off what the error IS, never what its text says. The shapes are the ones
 * openid-client / oauth4webapi and undici throw (federation-oidc's
 * `delegated-outage.test.mts` holds the real library to them).
 */

import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { isFederationUpstreamOutage } from "#/federation-grants/upstreamOutage.mjs";

/**
 * A Response from another copy of the fetch implementation — npm `undici`'s,
 * which a deployment's own `fetch` (a `ProxyAgent` setup) answers with, and
 * which oauth4webapi accepts by its tag — not an instance of the global class.
 */
class ForeignResponse {
	constructor(readonly status: number) {}
	get [Symbol.toStringTag](): string {
		return "Response";
	}
}

const coded = (code: string) => Object.assign(new Error(`connect ${code}`), { code });
const clientError = (code: string, cause: unknown) =>
	Object.assign(new Error("client error", { cause }), { name: "ClientError", code });

describe("isFederationUpstreamOutage", () => {
	it.each([
		["an abort", Object.assign(new Error("aborted"), { name: "AbortError" })],
		["a timeout", Object.assign(new Error("timed out"), { name: "TimeoutError" })],
		[
			"openid-client's timeout over a TimeoutError",
			clientError("OAUTH_TIMEOUT", Object.assign(new Error("t"), { name: "TimeoutError" })),
		],
		["a refused connection", coded("ECONNREFUSED")],
		[
			"undici's fetch failure over a coded socket error",
			new TypeError("fetch failed", { cause: coded("ECONNRESET") }),
		],
		["undici's own socket code", new TypeError("fetch failed", { cause: coded("UND_ERR_SOCKET") })],
		[
			"a token endpoint answering 503, as openid-client raises it",
			clientError("OAUTH_RESPONSE_IS_NOT_CONFORM", new Response("down", { status: 503 })),
		],
		[
			"a token endpoint answering 502 with no body",
			clientError("OAUTH_RESPONSE_IS_NOT_CONFORM", new Response(null, { status: 502 })),
		],
		[
			"an OAuth error body under a 5xx status",
			Object.assign(new Error("server error"), {
				name: "ResponseBodyError",
				status: 503,
				error: "temporarily_unavailable",
			}),
		],
		[
			"a 503 from a deployment's own fetch (npm undici's Response), as openid-client raises it",
			clientError("OAUTH_RESPONSE_IS_NOT_CONFORM", new ForeignResponse(503)),
		],
		...(
			[
				// Connection codes a socket reports.
				"ECONNABORTED",
				"EPROTO",
				"ENETDOWN",
				"EHOSTDOWN",
				"ENETRESET",
				// undici's own family, whatever the member: this server's transport
				// or its composition, a 503 either way.
				"UND_ERR_CONNECT_TIMEOUT",
				"UND_ERR_CLOSED",
				"UND_ERR_DESTROYED",
				"UND_ERR_RES_CONTENT_LENGTH_MISMATCH",
				"UND_ERR_HEADERS_OVERFLOW",
				"UND_ERR_INVALID_ARG",
				// llhttp's parser errors (undici's HTTPParserError).
				"HPE_INVALID_CONSTANT",
				// Node's X509 verification codes, prefixed and not.
				"CERT_HAS_EXPIRED",
				"CERT_REVOKED",
				"UNABLE_TO_VERIFY_LEAF_SIGNATURE",
				"UNABLE_TO_DECRYPT_CERT_SIGNATURE",
				"DEPTH_ZERO_SELF_SIGNED_CERT",
				"INVALID_CA",
				"PATH_LENGTH_EXCEEDED",
				"INVALID_PURPOSE",
				"CRL_HAS_EXPIRED",
				"ERROR_IN_CERT_NOT_AFTER_FIELD",
				"OUT_OF_MEM",
				// Node's TLS codes and OpenSSL's, one with OpenSSL 3's slash.
				"ERR_TLS_CERT_ALTNAME_INVALID",
				"ERR_SSL_WRONG_VERSION_NUMBER",
				"ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE",
				// A URL fetch could not parse: nothing was sent.
				"ERR_INVALID_URL",
			] as const
		).map((code): [string, unknown] => [
			`undici's fetch failure over a ${code} cause — the TLS layer, the URL or the socket`,
			new TypeError("fetch failed", { cause: coded(code) }),
		]),
		[
			"undici's own error, raised without fetch's TypeError around it",
			Object.assign(new Error("other side closed"), {
				name: "SocketError",
				code: "UND_ERR_CLOSED",
			}),
		],
		[
			"a TLS verification error, raised without fetch's TypeError around it",
			Object.assign(new Error("certificate has expired"), { code: "CERT_HAS_EXPIRED" }),
		],
		[
			"undici's fetch failure over a coded socket error, raised in another realm",
			runInNewContext(
				'Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error("x"), { code: "ECONNRESET" }) })',
			),
		],
	])("reads %s as an outage", (_label, error) => {
		expect(isFederationUpstreamOutage(error)).toBe(true);
	});

	it.each([
		[
			"an OAuth refusal",
			Object.assign(new Error("refused"), {
				name: "ResponseBodyError",
				status: 400,
				error: "invalid_grant",
			}),
		],
		[
			"a 4xx the library would not read",
			clientError("OAUTH_RESPONSE_IS_NOT_CONFORM", new Response("", { status: 404 })),
		],
		[
			"an id_token that did not verify",
			clientError("OAUTH_JWT_CLAIM_COMPARISON_FAILED", undefined),
		],
		[
			"a message that only SAYS it is an outage",
			new Error("connect ECONNREFUSED (fetch failed) 503"),
		],
		["a thrown non-error", "ECONNREFUSED"],
		["nothing", undefined],
		[
			"a refusal whose parsed IdP body says 503",
			Object.assign(new Error("refused", { cause: { status: 503, error: "invalid_client" } }), {
				name: "ResponseBodyError",
				status: 400,
				error: "invalid_client",
			}),
		],
		[
			"a refusal whose parsed IdP body names a connection code",
			Object.assign(new Error("refused", { cause: { code: "ECONNRESET" } }), {
				name: "ResponseBodyError",
				status: 400,
			}),
		],
		[
			"a refusal whose parsed IdP body names a timeout",
			Object.assign(new Error("refused", { cause: { name: "TimeoutError" } }), {
				name: "ResponseBodyError",
				status: 400,
			}),
		],
		["a thrown plain object that looks like a timeout", { name: "TimeoutError" }],
		["a thrown plain object that carries a 5xx status", { status: 503 }],
		...(
			[
				// An adapter's validation error, a token library's, a programming
				// error: none says anything about the transport.
				"OAUTH_INVALID_RESPONSE",
				"ERR_JWT_EXPIRED",
				"ERR_INVALID_ARG_TYPE",
				// Starts like undici's family, and is not one of its codes.
				"UND_ERR_not_a_code",
			] as const
		).map((code): [string, unknown] => [
			`a TypeError over a cause whose code, ${code}, is no transport's`,
			new TypeError("invalid response", {
				cause: Object.assign(new Error("the answer is not one"), { code }),
			}),
		]),
		[
			"a token library's error raised on its own",
			Object.assign(new Error('"exp" claim timestamp check failed'), { code: "ERR_JWT_EXPIRED" }),
		],
		[
			"a connection code five causes down, past where the walk looks",
			new Error("1", {
				cause: new Error("2", {
					cause: new Error("3", { cause: new Error("4", { cause: coded("ECONNRESET") }) }),
				}),
			}),
		],
		[
			"an Error whose every field throws when read",
			Object.defineProperties(new Error("hostile"), {
				name: {
					get: () => {
						throw new Error("trap");
					},
				},
				code: {
					get: () => {
						throw new Error("trap");
					},
				},
				status: {
					get: () => {
						throw new Error("trap");
					},
				},
				cause: {
					get: () => {
						throw new Error("trap");
					},
				},
			}),
		],
		[
			"a 404 from a deployment's own fetch",
			clientError("OAUTH_RESPONSE_IS_NOT_CONFORM", new ForeignResponse(404)),
		],
	])("reads %s as no outage", (_label, error) => {
		expect(isFederationUpstreamOutage(error)).toBe(false);
	});

	it("follows a connection code four causes down, where the walk still looks", () => {
		expect(
			isFederationUpstreamOutage(
				new Error("1", {
					cause: new Error("2", { cause: new Error("3", { cause: coded("ECONNRESET") }) }),
				}),
			),
		).toBe(true);
	});

	it("reads an Error by its tag, and no plain object, where the runtime has no Error.isError (Node 22)", () => {
		// The engines floor is Node 22, which has no Error.isError: the fallback
		// is what runs there, and a value whose prototype cannot be read must
		// not make it throw.
		const brand = Object.getOwnPropertyDescriptor(Error, "isError");
		delete (Error as { isError?: unknown }).isError;
		try {
			expect(
				isFederationUpstreamOutage(
					runInNewContext('Object.assign(new Error("x"), { code: "ECONNRESET" })'),
				),
			).toBe(true);
			expect(isFederationUpstreamOutage(coded("ECONNREFUSED"))).toBe(true);
			expect(isFederationUpstreamOutage({ code: "ECONNREFUSED" })).toBe(false);
			const unreadable = new Proxy(
				{},
				{
					getPrototypeOf() {
						throw new Error("trap");
					},
				},
			);
			expect(isFederationUpstreamOutage(unreadable)).toBe(false);
		} finally {
			if (brand) Object.defineProperty(Error, "isError", brand);
		}
	});

	it("never throws on what it is asked about", () => {
		const hostile = new Proxy(
			{},
			{
				get() {
					throw new Error("trap");
				},
			},
		);
		expect(isFederationUpstreamOutage(hostile)).toBe(false);
	});
});
