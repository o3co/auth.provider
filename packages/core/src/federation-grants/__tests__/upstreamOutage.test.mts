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

import { describe, expect, it } from "vitest";
import { isFederationUpstreamOutage } from "#/federation-grants/upstreamOutage.mjs";

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
	])("reads %s as no outage", (_label, error) => {
		expect(isFederationUpstreamOutage(error)).toBe(false);
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
