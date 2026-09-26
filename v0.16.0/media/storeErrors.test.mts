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
 * The Store-exchange errors on their own: which transport codes survive into
 * what is thrown, and the shape of the two named errors — what a reporter
 * reads by name, and no `status` an Express error handler would answer with.
 * Synthetic error chains, because a real transport on this Node does not
 * produce every code (undici's parser errors carry no `HPE_*` code here); the
 * credential suite drives the same errors through the wire.
 */

import { describe, expect, it } from "vitest";
import { StoreCredentialRefusedError, StoreTransportError } from "#/index.mjs";
import { requestFailure, transportCode } from "#/repositories/storeErrors.mjs";

const SECRET = "0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a";

/** `fetch`'s shape: a TypeError whose cause chain carries the transport's error. */
const chain = (...codes: unknown[]): unknown =>
	codes.reduceRight<unknown>((cause, code) => {
		const error = new Error("transport") as Error & { code?: unknown };
		error.code = code;
		if (cause !== undefined) error.cause = cause;
		return error;
	}, undefined);

describe("transportCode", () => {
	it("keeps a code an operator can act on, found on the error or its causes", () => {
		const kept = [
			"ECONNREFUSED",
			"ENOTFOUND",
			"ECONNRESET",
			"EPROTO",
			"CERT_HAS_EXPIRED",
			"CERT_NOT_YET_VALID",
			"DEPTH_ZERO_SELF_SIGNED_CERT",
			"ERR_TLS_CERT_ALTNAME_INVALID",
			"ERR_SSL_WRONG_VERSION_NUMBER",
			"ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION",
			// OpenSSL 3's name for a TLS 1.2 handshake failure alert: a slash in it.
			"ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE",
			"UND_ERR_SOCKET",
			"UND_ERR_HEADERS_OVERFLOW",
			"HPE_INVALID_HEADER_TOKEN",
			"HPE_INVALID_CONSTANT",
		];
		expect(kept.map((code) => transportCode(chain(undefined, code)))).toEqual(kept);
		expect(transportCode(chain(undefined, undefined, "ECONNREFUSED"))).toBe("ECONNREFUSED");
	});

	it("keeps nothing else — not a lowercase or unknown code, not a value, not one past the depth it reads", () => {
		const dropped = [
			"hpe_invalid_header_token",
			"HPE_",
			"ERR_SSL_",
			"ERR_SSL_/",
			"ERR_SSL_SSL/TLS ALERT",
			"ERR_SOMETHING_ELSE",
			`E${SECRET}`,
			`UND_ERR_${SECRET}`,
			`HPE_${SECRET.toUpperCase()}${SECRET.toUpperCase()}`,
			42,
			{ toString: () => "ECONNREFUSED" },
		];
		expect(dropped.map((code) => transportCode(chain(undefined, code)))).toEqual(
			dropped.map(() => undefined),
		);
		expect(
			transportCode(chain(undefined, undefined, undefined, undefined, "ECONNREFUSED")),
		).toBeUndefined();
	});
});

describe("requestFailure: which reason a failed request is", () => {
	/** undici's shape for "other side closed": a SocketError carrying the socket's byte counts. */
	const socketClosed = (bytesRead: number): unknown =>
		Object.assign(new TypeError("fetch failed"), {
			cause: Object.assign(new Error("other side closed"), {
				name: "SocketError",
				code: "UND_ERR_SOCKET",
				socket: { bytesRead, bytesWritten: 120 },
			}),
		});
	const named = (name: string, code?: string): unknown =>
		Object.assign(new TypeError("fetch failed"), {
			cause: Object.assign(new Error("transport"), {
				name,
				...(code === undefined ? {} : { code }),
			}),
		});
	const messages = { unreachable: "u", malformed: "m", closed: "c" };

	it("names a closed connection for what it is, whatever the socket had read — a pooled keep-alive socket has read a whole earlier answer", () => {
		const cases: [string, unknown, string][] = [
			["closed before any byte", socketClosed(0), "connection_closed"],
			[
				"closed after bytes (a 1xx, a cut head, or an earlier answer on a reused socket)",
				socketClosed(124),
				"connection_closed",
			],
			["reset", named("Error", "ECONNRESET"), "connection_closed"],
			["written after the peer closed", named("Error", "EPIPE"), "connection_closed"],
			["parser refused the head", named("HTTPParserError"), "malformed_response"],
			[
				"parser code where the runtime sets one",
				named("Error", "HPE_INVALID_CONSTANT"),
				"malformed_response",
			],
			[
				"head over the size limit",
				named("HeadersOverflowError", "UND_ERR_HEADERS_OVERFLOW"),
				"malformed_response",
			],
			["refused", named("Error", "ECONNREFUSED"), "unreachable"],
			["DNS", named("Error", "ENOTFOUND"), "unreachable"],
			["TLS", named("Error", "ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE"), "unreachable"],
			["no code at all", named("Error"), "unreachable"],
		];
		expect(cases.map(([what, err]) => [what, requestFailure(err, messages).reason])).toEqual(
			cases.map(([what, , reason]) => [what, reason]),
		);
	});
});

describe("the named errors", () => {
	it("a refused credential carries the Store's status as storeStatus — never as status, which Express and http-errors answer with", () => {
		const error = new StoreCredentialRefusedError("https://store.test/authenticate", 401);
		expect(error.name).toBe("StoreCredentialRefusedError");
		expect(error.storeStatus).toBe(401);
		expect("status" in error).toBe(false);
		expect("statusCode" in error).toBe(false);
	});

	it("a transport failure is a StoreTransportError with a reason, at most a code, and no cause or status", () => {
		const error = new StoreTransportError(
			"HttpUserRepository: request to https://store.test/authenticate could not be reached",
			"unreachable",
			"ECONNREFUSED",
		);
		expect(error).toBeInstanceOf(Error);
		expect(error.name).toBe("StoreTransportError");
		expect(error.reason).toBe("unreachable");
		expect(error.code).toBe("ECONNREFUSED");
		expect(error.cause).toBeUndefined();
		expect("status" in error).toBe(false);
		expect("statusCode" in error).toBe(false);
		expect(new StoreTransportError("x", "unreadable").code).toBeUndefined();
	});
});
