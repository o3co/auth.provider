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
 * The token route's domain body (#593, D10).
 *
 * Every field here is an *assertion*: something the caller claims about the
 * grant it is asking against, which core then checks. None of them widens
 * anything — a scope the grant does not carry is a refusal, not a request —
 * so the parser's whole job is to hand core exactly what the caller wrote, or
 * to refuse before core is asked at all.
 *
 * What it deliberately does NOT do is judge. `min_ttl` is handed over as a
 * number whatever its size: whether it is negative, or larger than the
 * connection permits, is core's decision and comes back as
 * `invalid_request/min_ttl_out_of_range` — one answer for one question, rather
 * than two layers each with their own idea of the bound.
 */

import { describe, expect, it } from "vitest";
import { parseFederationGrantTokenRequest } from "#/parse.mjs";

const ok = (body: unknown) => {
	const parsed = parseFederationGrantTokenRequest(body);
	if (!parsed.ok) throw new Error(`expected a parse, got ${parsed.description}`);
	return parsed.value;
};

const rejected = (body: unknown) => {
	const parsed = parseFederationGrantTokenRequest(body);
	if (parsed.ok) throw new Error("expected a refusal");
	return parsed.description;
};

describe("parseFederationGrantTokenRequest", () => {
	it("takes the subject exactly as written", () => {
		// No trimming and no case folding: the comparison against the grant's
		// owner is exact, and a parser that normalised here would authorise a
		// subject the store never recorded.
		expect(ok({ sub: " Local-Subject " }).subject).toBe(" Local-Subject ");
	});

	it("requires a subject, because every grant-addressed route is addressed by one", () => {
		expect(rejected({})).toMatch(/sub/);
		expect(rejected({ sub: "" })).toMatch(/sub/);
		expect(rejected({ sub: 42 })).toMatch(/sub/);
	});

	it("takes the optional assertions and preserves them", () => {
		const parsed = ok({
			sub: "u",
			connection: "graph",
			resource: "https://graph.example",
			scope: "openid offline_access Files.Read",
		});
		expect(parsed.connection).toBe("graph");
		expect(parsed.resource).toBe("https://graph.example");
		// Split, never sorted, widened or defaulted: the order is the caller's
		// and the set is exactly what they asked for.
		expect(parsed.scope).toEqual(["openid", "offline_access", "Files.Read"]);
	});

	it("leaves an absent assertion absent rather than substituting a default", () => {
		const parsed = ok({ sub: "u" });
		expect(parsed.connection).toBeUndefined();
		expect(parsed.resource).toBeUndefined();
		expect(parsed.scope).toBeUndefined();
		expect(parsed.minTtlSeconds).toBeUndefined();
	});

	it("refuses an empty assertion rather than reading it as absent", () => {
		expect(rejected({ sub: "u", connection: "" })).toMatch(/connection/);
		expect(rejected({ sub: "u", resource: "" })).toMatch(/resource/);
		expect(rejected({ sub: "u", scope: "" })).toMatch(/scope/);
		expect(rejected({ sub: "u", scope: "   " })).toMatch(/scope/);
	});

	it("takes min_ttl as a number or as the string a form body carries", () => {
		expect(ok({ sub: "u", min_ttl: 60 }).minTtlSeconds).toBe(60);
		expect(ok({ sub: "u", min_ttl: "60" }).minTtlSeconds).toBe(60);
		// Fractions are a legitimate ask and core's bound accepts any finite
		// non-negative number within the connection's ceiling.
		expect(ok({ sub: "u", min_ttl: "0.5" }).minTtlSeconds).toBe(0.5);
	});

	it("hands a min_ttl core will refuse to core, rather than refusing it here", () => {
		// Two layers with their own idea of the bound is two answers to one
		// question, and the connection's ceiling is not knowable here.
		expect(ok({ sub: "u", min_ttl: -1 }).minTtlSeconds).toBe(-1);
		expect(ok({ sub: "u", min_ttl: 999_999_999 }).minTtlSeconds).toBe(999_999_999);
	});

	it("refuses numeric syntax that is not a number at all", () => {
		for (const min_ttl of ["", "soon", "60s", "1e", Number.NaN, Number.POSITIVE_INFINITY, {}, []]) {
			expect(rejected({ sub: "u", min_ttl }), JSON.stringify(min_ttl)).toMatch(/min_ttl/);
		}
	});

	it("refuses a repeated parameter rather than picking one of the two", () => {
		// A form body with `sub` twice arrives as an array. Neither value is
		// the one the caller meant, and choosing is how a proxy and a server
		// come to disagree about who is being asked for.
		expect(rejected({ sub: ["a", "b"] })).toMatch(/sub/);
		expect(rejected({ sub: "u", connection: ["a", "b"] })).toMatch(/connection/);
	});

	it("refuses a nested object where a value belongs", () => {
		expect(rejected({ sub: { toString: "u" } })).toMatch(/sub/);
		expect(rejected({ sub: "u", resource: { href: "x" } })).toMatch(/resource/);
	});

	it("refuses a field it does not know", () => {
		// A caller that sent `scopes` meaning `scope`, or `subject` meaning
		// `sub`, has asked for something this route did not do — answering as
		// if the field had not been there is how that goes unnoticed.
		expect(rejected({ sub: "u", scopes: "openid" })).toBe("unexpected_parameter");
		expect(rejected({ sub: "u", audience: "x" })).toBe("unexpected_parameter");
	});

	it("answers with an identifier and never with the caller's own field name", () => {
		// Two reasons it does not name the field. It is caller-supplied, and
		// `error_description` ends up in logs and dashboards; and the point of
		// an identifier is that something can branch on it, which a sentence
		// containing an arbitrary string cannot be.
		expect(rejected({ sub: "u", "</script>": "x" })).toBe("unexpected_parameter");
		expect(rejected({})).toBe("sub_required");
		expect(rejected({ sub: ["a", "b"] })).toBe("duplicate_sub");
		expect(rejected({ sub: 42 })).toBe("invalid_sub");
		expect(rejected("sub=u")).toBe("invalid_body");
		for (const description of [
			rejected({ sub: "u", connection: "" }),
			rejected({ sub: "u", scope: " " }),
			rejected({ sub: "u", min_ttl: "60s" }),
		]) {
			expect(description).toMatch(/^[a-z][a-z_]*$/);
		}
	});

	it("permits the client authentication fields alongside its own", () => {
		// They arrive in the same body for `client_secret_post` and
		// `private_key_jwt`, and the middleware that reads them has already run.
		expect(() =>
			ok({
				sub: "u",
				client_id: "worker",
				client_secret: "s",
				client_assertion: "jwt",
				client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			}),
		).not.toThrow();
	});

	it("refuses a body that is not an object", () => {
		for (const body of [undefined, null, "sub=u", 42, []]) {
			expect(rejected(body), JSON.stringify(body)).toBeTruthy();
		}
	});
});
