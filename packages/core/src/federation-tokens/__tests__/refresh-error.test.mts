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
import { classifyFederationRefreshError } from "#/federation-tokens/refresh-error.mjs";

/** An error shaped as openid-client v6 surfaces a token-endpoint rejection. */
const upstream = (
	fields: { error?: unknown; status?: unknown },
	headers?: Record<string, string>,
): Error =>
	Object.assign(new Error("server responded with an error in the response body"), fields, {
		...(headers !== undefined ? { response: new Response(null, { status: 400, headers }) } : {}),
	});

describe("classifyFederationRefreshError (#593, D12)", () => {
	describe("the reason — what the session-bound route has always acted on (SF-13)", () => {
		it("reads a rejected refresh token off the structured error code", () => {
			for (const code of ["invalid_grant", "invalid_token"]) {
				expect(
					classifyFederationRefreshError(upstream({ error: code, status: 400 })),
				).toMatchObject({
					reason: "invalid_grant",
					structured: true,
				});
			}
		});

		it("reads a rate limit off the code or the status", () => {
			expect(classifyFederationRefreshError(upstream({ error: "too_many_requests" })).reason).toBe(
				"rate_limited",
			);
			expect(classifyFederationRefreshError(upstream({ status: 429 })).reason).toBe("rate_limited");
		});

		it("reads an upstream outage off a 5xx status, and a network failure off the cause chain", () => {
			expect(classifyFederationRefreshError(upstream({ status: 503 }))).toMatchObject({
				reason: "network",
				structured: true,
			});
			const fetchFailed = new TypeError("fetch failed", {
				cause: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }),
			});
			expect(classifyFederationRefreshError(fetchFailed)).toMatchObject({
				reason: "network",
				structured: true,
			});
		});

		it("keeps the order the session-bound route has always had, where two readings apply", () => {
			// A rejected token before a rate limit, a rate limit before an outage, an
			// outage before a network code. The message fallback reads an outage
			// only, so a message naming both is an outage.
			const network = { code: "ECONNREFUSED" };
			expect(
				classifyFederationRefreshError(upstream({ error: "invalid_grant", status: 429 })).reason,
			).toBe("invalid_grant");
			expect(
				classifyFederationRefreshError(upstream({ error: "too_many_requests", status: 503 }))
					.reason,
			).toBe("rate_limited");
			expect(
				classifyFederationRefreshError(Object.assign(upstream({ status: 429 }), network)).reason,
			).toBe("rate_limited");
			expect(
				classifyFederationRefreshError(Object.assign(upstream({ status: 502 }), network)).reason,
			).toBe("network");
			expect(
				classifyFederationRefreshError(new Error("invalid_grant after a 502 from the proxy"))
					.reason,
			).toBe("network");
		});

		it("walks the cause chain four deep, and no deeper", () => {
			const wrap = (depth: number): unknown => {
				let error: unknown = Object.assign(new Error("connect"), { code: "ETIMEDOUT" });
				for (let i = 0; i < depth; i++) error = new TypeError("fetch failed", { cause: error });
				return error;
			};
			for (const depth of [0, 1, 2, 3]) {
				expect(classifyFederationRefreshError(wrap(depth)).reason, String(depth)).toBe("network");
			}
			expect(classifyFederationRefreshError(wrap(4)).reason).toBe("unknown");
		});

		describe("a rejected refresh token is a verdict, and an outage is none, whatever its body says", () => {
			// Acting on `invalid_grant` ends the session's upstream tokens (the
			// session-bound route) or sends the user through consent again (a
			// federation grant). An upstream that is down says nothing about the
			// credential, even when the body it answered with names a code.
			it("reads an outage, not a rejected token, off a 5xx status on the error", () => {
				for (const status of [500, 502, 503, 599]) {
					for (const error of ["invalid_grant", "invalid_token"]) {
						expect(
							classifyFederationRefreshError(upstream({ error, status })),
							`${status} ${error}`,
						).toEqual({ reason: "network", structured: true, upstreamCode: error });
					}
				}
			});

			it("reads an outage off anything isFederationUpstreamOutage reads as one", () => {
				const rejected = { error: "invalid_grant" };
				const shapes: Record<string, unknown> = {
					"a 5xx on the error's cause": Object.assign(
						new Error("wrapped", {
							cause: Object.assign(new Error("upstream"), { status: 502 }),
						}),
						rejected,
					),
					"the 5xx Response the error was raised over": Object.assign(
						new Error('"response" is not a conform Token Endpoint response', {
							cause: new Response(null, { status: 503 }),
						}),
						rejected,
					),
					"a request given up on": Object.assign(new Error("aborted"), {
						name: "TimeoutError",
						...rejected,
					}),
					"a transport code under fetch's TypeError": Object.assign(
						new TypeError("fetch failed", {
							cause: Object.assign(new Error("other side closed"), { code: "UND_ERR_SOCKET" }),
						}),
						rejected,
					),
				};
				for (const [label, error] of Object.entries(shapes)) {
					expect(classifyFederationRefreshError(error), label).toMatchObject({
						reason: "network",
						structured: true,
					});
				}
			});

			it("reads an outage off a 5xx status on a thrown value that is not an Error", () => {
				// What a hand-written adapter may throw. The status is read on the
				// value itself, as it always was; only the ordering changed.
				expect(classifyFederationRefreshError({ error: "invalid_grant", status: 503 })).toEqual({
					reason: "network",
					structured: true,
					upstreamCode: "invalid_grant",
				});
			});

			it("reads no outage off the IdP's parsed error body, which is openid-client's cause", () => {
				// ResponseBodyError carries the IdP's JSON body as its `cause`: a plain
				// object whose every field the IdP chose. A connection code or a 5xx
				// status written there is not this server's transport failing.
				const answered = (body: Record<string, unknown>) =>
					Object.assign(
						new Error("server responded with an error in the response body", { cause: body }),
						{ name: "ResponseBodyError", error: body.error, status: 400 },
					);
				expect(
					classifyFederationRefreshError(
						answered({ error: "login_required", code: "ECONNREFUSED", status: 503 }),
					),
				).toEqual({ reason: "unknown", structured: false, upstreamCode: "login_required" });
				expect(
					classifyFederationRefreshError(answered({ error: "invalid_grant", code: "ETIMEDOUT" })),
				).toMatchObject({ reason: "invalid_grant", structured: true });
			});

			it("still reads a network code on the thrown value itself, and on causes that are Errors", () => {
				// What a hand-written adapter may throw, and what fetch raises.
				expect(classifyFederationRefreshError({ code: "ETIMEDOUT" })).toMatchObject({
					reason: "network",
					structured: true,
				});
				expect(
					classifyFederationRefreshError(
						new TypeError("fetch failed", {
							cause: Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" }),
						}),
					),
				).toMatchObject({ reason: "network", structured: true });
			});

			it("still reads a rejected token off a structured code under a 4xx", () => {
				for (const status of [400, 401, 429]) {
					expect(
						classifyFederationRefreshError(upstream({ error: "invalid_grant", status })),
						String(status),
					).toMatchObject({ reason: "invalid_grant", structured: true });
				}
			});
		});

		it("never reads a rejected token off a message", () => {
			// A message is whatever the library, a proxy or the upstream wrote.
			// Kept for adapters that throw a plain Error, the fallback reads an
			// outage from it and nothing else.
			expect(classifyFederationRefreshError(new Error("invalid_grant: token revoked"))).toEqual({
				reason: "unknown",
				structured: false,
			});
			expect(classifyFederationRefreshError("invalid_grant")).toEqual({
				reason: "unknown",
				structured: false,
			});
		});

		it("falls back to the message for an outage when the error carries nothing structured, and says that it did", () => {
			expect(classifyFederationRefreshError(new Error("upstream said 502"))).toEqual({
				reason: "network",
				structured: false,
			});
			expect(classifyFederationRefreshError("temporarily_unavailable")).toEqual({
				reason: "network",
				structured: false,
			});
			// What else the error carries is reported on this path too.
			expect(
				classifyFederationRefreshError(
					Object.assign(new Error("invalid_grant, said the gateway"), { error: "server_error" }),
				),
			).toEqual({ reason: "unknown", structured: false, upstreamCode: "server_error" });
			expect(
				classifyFederationRefreshError(
					Object.assign(new Error("upstream said 502"), {
						response: new Response(null, { status: 502, headers: { "retry-after": "9" } }),
					}),
				),
			).toEqual({ reason: "network", structured: false, retryAfterSeconds: 9 });
		});

		it("is unknown for everything else", () => {
			expect(classifyFederationRefreshError(new Error("boom"))).toEqual({
				reason: "unknown",
				structured: false,
			});
			expect(classifyFederationRefreshError(undefined)).toEqual({
				reason: "unknown",
				structured: false,
			});
			expect(
				classifyFederationRefreshError(upstream({ error: "invalid_client", status: 401 })),
			).toMatchObject({ reason: "unknown" });
		});
	});

	describe("the upstream's error code", () => {
		it("is reported when it is a code this provider knows", () => {
			expect(
				classifyFederationRefreshError(upstream({ error: "invalid_client", status: 401 })),
			).toEqual({ reason: "unknown", structured: false, upstreamCode: "invalid_client" });
			expect(
				classifyFederationRefreshError(upstream({ error: "invalid_grant" })).upstreamCode,
			).toBe("invalid_grant");
		});

		it("knows the codes of the token endpoint, of a protected resource and of OpenID Connect, each by name", () => {
			// An allow-list is only as good as what is on it: a code that fell off
			// would turn a useful `upstream_rejected/<code>` into `unknown`.
			for (const code of [
				"invalid_request",
				"invalid_client",
				"invalid_grant",
				"unauthorized_client",
				"unsupported_grant_type",
				"invalid_scope",
				"access_denied",
				"server_error",
				"temporarily_unavailable",
				"invalid_token",
				"insufficient_scope",
				"invalid_target",
				"too_many_requests",
				"interaction_required",
				"login_required",
				"consent_required",
				"account_selection_required",
			]) {
				expect(
					classifyFederationRefreshError(upstream({ error: code, status: 400 })).upstreamCode,
					code,
				).toBe(code);
			}
		});

		it("is left out for anything else: every pattern that fits a code fits an opaque token too", () => {
			// An upstream that echoes what it was sent must not get a refresh token
			// repeated through the one field a caller puts in a response.
			const notKnown = [
				"SENTINEL-refresh-token",
				"8xLOxBtZp8",
				"vendor_specific_code",
				"INVALID_GRANT",
				"",
				"x".repeat(65),
				"invalid grant",
				'say "cheese"',
				"line\nbreak",
				42,
				{ toString: () => "invalid_grant" },
			];
			for (const error of notKnown) {
				expect(
					classifyFederationRefreshError(upstream({ error, status: 400 })),
					JSON.stringify(error),
				).not.toHaveProperty("upstreamCode");
			}
			expect(classifyFederationRefreshError(new Error("invalid_client"))).not.toHaveProperty(
				"upstreamCode",
			);
		});
	});

	describe("Retry-After", () => {
		it("is read off the response as whole seconds", () => {
			expect(
				classifyFederationRefreshError(upstream({ status: 429 }, { "retry-after": "120" })),
			).toEqual({ reason: "rate_limited", structured: true, retryAfterSeconds: 120 });
		});

		it("is read from one second up to a day, and no further", () => {
			const read = (value: string) =>
				classifyFederationRefreshError(upstream({ status: 429 }, { "retry-after": value }))
					.retryAfterSeconds;
			expect(read("1")).toBe(1);
			expect(read("86400")).toBe(86_400);
			expect(read("86401")).toBeUndefined();
		});

		it("is left out when it is a date, not a number, not positive, or absurd", () => {
			for (const value of ["Wed, 21 Oct 2026 07:28:00 GMT", "soon", "0", "-5", "1.5", "99999999"]) {
				expect(
					classifyFederationRefreshError(upstream({ status: 429 }, { "retry-after": value })),
					value,
				).toEqual({ reason: "rate_limited", structured: true });
			}
		});

		it("is left out when the error carries no response to read", () => {
			expect(classifyFederationRefreshError(upstream({ status: 429 }))).toEqual({
				reason: "rate_limited",
				structured: true,
			});
			const hostile = Object.assign(new Error("x"), {
				status: 429,
				response: {
					headers: {
						get: () => {
							throw new Error("nope");
						},
					},
				},
			});
			expect(classifyFederationRefreshError(hostile)).toEqual({
				reason: "rate_limited",
				structured: true,
			});
		});
	});
});
