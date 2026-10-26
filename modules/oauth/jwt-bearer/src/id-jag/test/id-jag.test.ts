import type { GrantInput } from "@mod/grants";
import { describe, expect, it } from "vitest";
import { admit, asked, type IdJag, idJagTyp, read, recheck } from "../id-jag.ts";

const jkt = "A".repeat(43);
const header = { alg: "ES256", typ: "oauth-id-jag+jwt" };
const claims = {
	iss: "https://idp.example",
	sub: "alice",
	aud: "https://as.example",
	client_id: "agent",
	jti: "j1",
	iat: 1_800_000_000,
	exp: 1_800_000_300,
	scope: "chat.read chat.history",
	resource: "https://api.example",
};
const readOf = (changed: Record<string, unknown>, h: Record<string, unknown> = header) =>
	read({ header: h, claims: { ...claims, ...changed } });
const without = (name: keyof typeof claims) => {
	const { [name]: _, ...rest } = claims;
	return read({ header, claims: rest });
};
const malformed = { kind: "invalid", reason: "missing or malformed claims" };

describe("id-jag: reading a verified ID-JAG", () => {
	it("reads the client, scope, resources and key it names", () => {
		expect(idJagTyp).toBe("oauth-id-jag+jwt");
		expect(read({ header, claims })).toEqual({
			kind: "id-jag",
			clientId: "agent",
			scope: ["chat.read", "chat.history"],
			resources: ["https://api.example"],
		});
		expect(
			readOf({ resource: ["https://a.example", "https://b.example/x"], cnf: { jkt } }),
		).toEqual({
			kind: "id-jag",
			clientId: "agent",
			scope: ["chat.read", "chat.history"],
			resources: ["https://a.example", "https://b.example/x"],
			keyThumbprint: jkt,
		});
		const { scope: _, resource: __, ...bare } = claims;
		expect(read({ header, claims: bare })).toEqual({ kind: "id-jag", clientId: "agent" });
	});

	it("takes its type as external-jwt reads one, and no other", () => {
		expect(readOf({}, { ...header, typ: "application/OAuth-ID-JAG+JWT" }).kind).toBe("id-jag");
		for (const typ of [undefined, "JWT", "at+jwt"])
			expect(readOf({}, { alg: "ES256", ...(typ ? { typ } : {}) }), String(typ)).toEqual({
				kind: "invalid",
				reason: "untrusted signer",
			});
	});

	it("takes one audience alone", () => {
		expect(readOf({ aud: ["https://as.example"] }).kind).toBe("id-jag");
		expect(readOf({ aud: ["https://as.example", "https://other.example"] })).toEqual({
			kind: "invalid",
			reason: "wrong audience",
		});
	});

	it("needs iat and a client_id of 1 to 255 characters", () => {
		expect(without("iat")).toEqual(malformed);
		expect(without("client_id")).toEqual(malformed);
		for (const client_id of [7, "", "c".repeat(256)])
			expect(readOf({ client_id }), String(client_id)).toEqual(malformed);
		expect(readOf({ client_id: "c".repeat(255) }).kind).toBe("id-jag");
		expect(readOf({ iat: "1800000000" })).toEqual(malformed);
	});

	it("refuses a scope signed empty or of no RFC 6749 form, which would read as none", () => {
		for (const scope of ["", " ", "a  b", 'a"b', 3, ["a"]])
			expect(readOf({ scope }), JSON.stringify(scope)).toEqual(malformed);
	});

	it("takes resources only as absolute URIs with no fragment (RFC 8707 §2)", () => {
		for (const resource of [
			"/relative",
			"api.example",
			[],
			["https://a.example", 5],
			"https://api.example/x#a",
			"https://api.example/x#",
			["https://a.example", "https://b.example#f"],
		])
			expect(readOf({ resource }), JSON.stringify(resource)).toEqual(malformed);
	});

	it("takes a cnf naming a DPoP key's thumbprint alone", () => {
		for (const cnf of [
			"x",
			[jkt],
			{},
			{ "x5t#S256": jkt },
			{ jkt, "x5t#S256": jkt },
			{ jkt: "A".repeat(42) },
			{ jkt: `${"A".repeat(42)}=` },
		])
			expect(readOf({ cnf }), JSON.stringify(cnf)).toEqual(malformed);
	});

	it("checks authorization details' form and drops them, refusing them where no scope says what was allowed", () => {
		const details = [{ type: "payment_initiation", amount: 1 }];
		expect(readOf({ authorization_details: details }).kind).toBe("id-jag");
		for (const authorization_details of [{ type: "x" }, [{}], [{ type: "" }], ["x"]])
			expect(readOf({ authorization_details }), JSON.stringify(authorization_details)).toEqual(
				malformed,
			);
		const { scope: _, ...noScope } = claims;
		expect(read({ header, claims: { ...noScope, authorization_details: details } })).toEqual({
			kind: "invalid",
			reason: "authorization details are not served",
		});
	});

	it("refuses a tenant, and an actor of no form", () => {
		for (const changed of [{ tenant: "t" }, { aud_tenant: "t" }])
			expect(readOf(changed)).toEqual({ kind: "invalid", reason: "tenant not taken" });
		expect(readOf({ act: { sub: "agent-runner" } }).kind).toBe("id-jag");
		for (const act of ["x", {}, { sub: 1 }])
			expect(readOf({ act }), JSON.stringify(act)).toEqual(malformed);
	});

	it("reads the claims' own alone, never one an object inherits", () => {
		const inherited = Object.assign(Object.create({ client_id: "agent", iat: 1 }), {
			...claims,
		});
		delete inherited.client_id;
		delete inherited.iat;
		expect(read({ header, claims: inherited })).toEqual(malformed);
	});
});

const idJag = (changed: Partial<IdJag> = {}): IdJag => ({
	kind: "id-jag",
	clientId: "agent",
	...changed,
});
const client = (id: string, kind: "public" | "confidential") =>
	({ id, kind }) as unknown as GrantInput["client"];
const dpop = (confirmation: string): GrantInput["binding"] => ({
	member: "jkt",
	confirmation,
	tokenType: "DPoP",
});

describe("id-jag: the client and the key presenting it", () => {
	it("is presented by the confidential client it names alone", () => {
		expect(admit(idJag(), { client: client("agent", "confidential") })).toEqual({
			kind: "admitted",
		});
		expect(admit(idJag(), { client: client("agent", "public") })).toEqual({
			kind: "invalid",
			reason: "the profile needs a confidential client",
		});
		expect(admit(idJag(), { client: client("other", "confidential") })).toEqual({
			kind: "invalid",
			reason: "assertion is for another client",
		});
	});

	it("proves by DPoP the key its cnf names, never by another binding or key", () => {
		const bound = idJag({ keyThumbprint: jkt });
		const agent = client("agent", "confidential");
		expect(admit(bound, { client: agent, binding: dpop(jkt) })).toEqual({ kind: "admitted" });
		const unproved = {
			kind: "invalid",
			reason: "the request does not prove the key the assertion names",
		};
		expect(admit(bound, { client: agent })).toEqual(unproved);
		expect(admit(bound, { client: agent, binding: dpop("B".repeat(43)) })).toEqual(unproved);
		const mtls = { member: "x5t#S256", confirmation: jkt, tokenType: "Bearer" } as const;
		expect(admit(bound, { client: agent, binding: mtls })).toEqual(unproved);
		// One naming no key takes any binding the request proves, or none.
		expect(admit(idJag(), { client: agent, binding: dpop(jkt) })).toEqual({ kind: "admitted" });
	});
});

describe("id-jag: what is asked, within what the ID-JAG allows", () => {
	const scoped = idJag({
		scope: ["chat.read", "chat.history"],
		resources: ["https://api.example"],
	});

	it("asks the request's own scope, else the ID-JAG's, within the ID-JAG's ceiling", () => {
		const ceiling = { scopes: ["chat.read", "chat.history"], audiences: ["https://api.example"] };
		expect(asked(scoped, "chat.read")).toEqual({ scope: "chat.read", ceiling });
		expect(asked(scoped, undefined)).toEqual({ scope: "chat.read chat.history", ceiling });
		expect(asked(scoped, "")).toEqual({ scope: "chat.read chat.history", ceiling });
	});

	it("leaves the scope to the client's defaults, unbounded by it, where the ID-JAG names none", () => {
		expect(asked(idJag(), undefined)).toEqual({ scope: undefined, ceiling: {} });
		expect(asked(idJag({ resources: ["https://api.example"] }), "")).toEqual({
			scope: undefined,
			ceiling: { audiences: ["https://api.example"] },
		});
	});

	it("checks again what is issued: a scope within the ID-JAG's and audiences among its resources", () => {
		const issued = { scope: ["chat.read"], audience: ["https://api.example"] };
		expect(recheck(scoped, issued)).toEqual({ kind: "ok" });
		expect(recheck(scoped, { ...issued, scope: ["chat.read", "admin"] })).toEqual({
			kind: "error",
			error: "invalid_scope",
		});
		expect(recheck(scoped, { ...issued, audience: ["https://other.example"] })).toEqual({
			kind: "error",
			error: "invalid_target",
		});
		expect(recheck(idJag(), { scope: ["anything"], audience: ["https://any.example"] })).toEqual({
			kind: "ok",
		});
	});
});
