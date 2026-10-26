import type { HttpRequest } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, defineModule, isUnavailable, kernelConfig, Unavailable } from "@mod/kernel";
import { beforeAll, beforeEach, expect, it } from "vitest";
import {
	type Binding,
	challengeOf,
	type Scene,
	type SenderBindings,
	senderBinding,
	senderBindings,
} from "../src/contract.ts";
import senderBindingModule from "../src/module.ts";

const reads: Scene[] = [];
beforeEach(() => {
	reads.length = 0;
});

/**
 * A kind proving a key in a header: `bad` is refused, `nonce` asks for a header, `own` answers its
 * own challenge, `down` is unavailable.
 */
const kind = (member: string, tokenType: string, header: string) =>
	defineModule({ name: `binding-${member}`, takes: [] }, (m) => [
		m.contribute(senderBindings).by(() => ({
			member,
			tokenType,
			read: async (request: HttpRequest, scene) => {
				const value = request.headers.get(header);
				if (!value) return { kind: "absent" };
				reads.push(scene);
				if (value === "bad") return { kind: "refused", error: "invalid_proof" };
				if (value === "nonce") {
					return { kind: "refused", error: "use_nonce", headers: { "x-nonce": "n1" } };
				}
				if (value === "own") {
					return { kind: "refused", error: "own", headers: { "www-authenticate": "DPoP own" } };
				}
				if (value === "down") return { kind: "refused", error: "down", unavailable: true };
				return { kind: "bound", confirmation: value };
			},
		})),
	]);

type Check =
	| {
			readonly kind: "valid";
			readonly subject: string;
			readonly binding?: Binding;
	  }
	| { readonly kind: "invalid"; readonly reason: string };

const bound = (member: string, confirmation: string, tokenType: string) => ({
	member,
	confirmation,
	tokenType,
});
const issued: Record<string, Check> = {
	plain: { kind: "valid", subject: "alice" },
	keyed: { kind: "valid", subject: "bob", binding: bound("jkt", "k1", "DPoP") },
	certified: { kind: "valid", subject: "carol", binding: bound("x5t", "c1", "Bearer") },
	stranger: { kind: "valid", subject: "dave", binding: bound("other", "o1", "Other") },
};
const tokens = {
	verifyAccess: async (token: string): Promise<Check> => {
		if (token === "down") throw new Unavailable("tokens");
		return issued[token] ?? { kind: "invalid", reason: "signature" };
	},
};

let b: SenderBindings;
beforeAll(async () => {
	const app = await assemble({
		modules: [
			http,
			issuerModule,
			senderBindingModule,
			kind("jkt", "DPoP", "x-proof"),
			kind("x5t", "Bearer", "x-cert"),
		],
		config: { ...kernelConfig(), ...httpConfig(), ...issuerConfig() },
	});
	b = app.get(senderBinding);
});

const presenting = (headers: Record<string, string>) =>
	b.admitted(testRequest({ headers: new Map(Object.entries(headers)) }), tokens);
const refusal = (status: number, challenge: string, error?: string) => ({
	kind: "refused",
	status,
	...(error ? { error } : {}),
	headers: { "www-authenticate": challenge },
});

it("challenges every scheme, with no error, when no token is presented in a scheme it knows [rfc6750-3.1-d] [rfc9449-7.2-b]", async () => {
	expect(await presenting({})).toEqual(refusal(401, "Bearer, DPoP"));
	expect(await presenting({ authorization: "Basic YTpi" })).toEqual(refusal(401, "Bearer, DPoP"));
	// A scheme with no credential after it presents no token either.
	for (const authorization of ["Bearer", "Bearer   ", "DPoP"]) {
		expect(await presenting({ authorization }), authorization).toEqual(
			refusal(401, "Bearer, DPoP"),
		);
	}
});

it("answers a malformed Authorization as an invalid request", async () => {
	const invalid = refusal(400, 'Bearer error="invalid_request"', "invalid_request");
	expect(await presenting({ authorization: "Bearer a b" })).toEqual(invalid);
	expect(await presenting({ authorization: "Bearer plain, Bearer plain" })).toEqual(invalid);
	// A token holds only RFC 6750's b64token characters.
	expect(await presenting({ authorization: "Bearer plain,x" })).toEqual(invalid);
});

it("admits a valid unbound token as Bearer, in any case of the scheme, without reading bindings [rfc6750-2.1-a]", async () => {
	expect(await presenting({ authorization: "bearer plain", "x-proof": "bad" })).toEqual({
		kind: "admitted",
		access: issued.plain,
	});
	expect(reads).toEqual([]);
});

it("refuses a token that is not valid, challenging the scheme it was presented in [rfc6750-3-b] [rfc6750-3-f] [rfc6750-3.1-b] [rfc9449-7.1-c]", async () => {
	expect(await presenting({ authorization: "Bearer forged" })).toEqual(
		refusal(401, 'Bearer error="invalid_token"', "invalid_token"),
	);
	expect(await presenting({ authorization: "DPoP forged" })).toEqual(
		refusal(401, 'DPoP error="invalid_token"', "invalid_token"),
	);
});

it("refuses a token presented in another scheme than its type, challenging its own [rfc9449-7.2-a]", async () => {
	expect(await presenting({ authorization: "Bearer keyed", "x-proof": "k1" })).toEqual(
		refusal(401, 'DPoP error="invalid_token"', "invalid_token"),
	);
	expect(await presenting({ authorization: "DPoP plain", "x-proof": "k1" })).toEqual(
		refusal(401, 'Bearer error="invalid_token"', "invalid_token"),
	);
	expect(await presenting({ authorization: "DPoP certified", "x-cert": "c1" })).toEqual(
		refusal(401, 'Bearer error="invalid_token"', "invalid_token"),
	);
	expect(reads).toEqual([]);
});

it("refuses a token bound by a member no kind writes", async () => {
	expect(await presenting({ authorization: "Bearer stranger" })).toEqual(
		refusal(401, 'Bearer error="invalid_token"', "invalid_token"),
	);
});

it("admits a bound token whose holder proves the same binding at the resource", async () => {
	expect(await presenting({ authorization: "DPoP keyed", "x-proof": "k1" })).toEqual({
		kind: "admitted",
		access: issued.keyed,
	});
	expect(reads).toEqual([{ kind: "resource", token: "keyed" }]);
	expect(await presenting({ authorization: "Bearer certified", "x-cert": "c1" })).toEqual({
		kind: "admitted",
		access: issued.certified,
	});
});

it("refuses a bound token when the request proves no binding or another key", async () => {
	const refused = refusal(401, 'DPoP error="invalid_token"', "invalid_token");
	expect(await presenting({ authorization: "DPoP keyed" })).toEqual(refused);
	expect(await presenting({ authorization: "DPoP keyed", "x-proof": "k2" })).toEqual(refused);
	expect(await presenting({ authorization: "Bearer certified", "x-cert": "c2" })).toEqual(
		refusal(401, 'Bearer error="invalid_token"', "invalid_token"),
	);
});

it("passes a kind's refusal code and headers through", async () => {
	expect(await presenting({ authorization: "DPoP keyed", "x-proof": "bad" })).toEqual(
		refusal(401, 'DPoP error="invalid_proof"', "invalid_proof"),
	);
	expect(await presenting({ authorization: "DPoP keyed", "x-proof": "nonce" })).toEqual({
		kind: "refused",
		status: 401,
		error: "use_nonce",
		headers: { "www-authenticate": 'DPoP error="use_nonce"', "x-nonce": "n1" },
	});
	// A kind's own challenge replaces the one admission writes.
	expect(await presenting({ authorization: "DPoP keyed", "x-proof": "own" })).toMatchObject({
		headers: { "www-authenticate": "DPoP own" },
	});
});

it("refuses two bindings as an invalid request", async () => {
	expect(
		await presenting({ authorization: "DPoP keyed", "x-proof": "k1", "x-cert": "c1" }),
	).toEqual(refusal(400, 'DPoP error="invalid_request"', "invalid_request"));
});

it("throws unavailable when the token's validity or its binding cannot be told", async () => {
	await expect(presenting({ authorization: "Bearer down" })).rejects.toSatisfy(isUnavailable);
	await expect(presenting({ authorization: "DPoP keyed", "x-proof": "down" })).rejects.toSatisfy(
		isUnavailable,
	);
});

it("challenges a kind's refusal in the scheme of the kind that refused", async () => {
	expect(
		await presenting({ authorization: "Bearer certified", "x-cert": "c1", "x-proof": "bad" }),
	).toEqual(refusal(401, 'DPoP error="invalid_proof"', "invalid_proof"));
	expect(
		await presenting({ authorization: "DPoP keyed", "x-proof": "k1", "x-cert": "bad" }),
	).toEqual(refusal(401, 'Bearer error="invalid_proof"', "invalid_proof"));
});

it("makes a resource's own challenge for a token it refuses, in the token's type", () => {
	expect(challengeOf("Bearer", "invalid_token")).toEqual({
		"www-authenticate": 'Bearer error="invalid_token"',
	});
	expect(challengeOf("DPoP", "insufficient_scope")).toEqual({
		"www-authenticate": 'DPoP error="insufficient_scope"',
	});
});
