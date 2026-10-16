import { describe, expect, it } from "vitest";
import { documentUrl, recordOf } from "../src/document/document.ts";

const id = "https://app.example/client.json";
const doc = {
	client_id: id,
	client_name: "App",
	redirect_uris: ["https://app.example/cb"],
};
const ceiling = { scopes: ["openid", "read"], audiences: ["https://api.example"] };
const record = (fields: Record<string, unknown>, limits = ceiling) =>
	recordOf(new URL(id), { ...doc, ...fields }, limits);
/** The client-allowance section of the record, or the refusal as it is. */
const allowances = (fields: Record<string, unknown>, limits = ceiling) => {
	const made = record(fields, limits);
	return "sections" in made ? made.sections["client-allowance"] : made;
};

describe("document URL", () => {
	it("takes an https URL with a path, written as the URL parser writes it", () => {
		expect(documentUrl(id)?.hostname).toBe("app.example");
		expect(documentUrl("https://app.example:8443/c")?.port).toBe("8443");
	});

	it.each([
		["plain http", "http://app.example/c"],
		["no path", "https://app.example"],
		["the root path", "https://app.example/"],
		["a query", "https://app.example/c?x=1"],
		["an empty query", "https://app.example/c?"],
		["a fragment", "https://app.example/c#x"],
		["an empty fragment", "https://app.example/c#"],
		["user information", "https://user@app.example/c"],
		["a password", "https://user:pw@app.example/c"],
		["a password alone", "https://:pw@app.example/c"],
		["a dot segment", "https://app.example/a/./c"],
		["a dot-dot segment", "https://app.example/a/../c"],
		["an encoded dot segment", "https://app.example/a/%2e%2e/c"],
		["an IPv4 literal", "https://192.0.2.1/c"],
		["an IPv4 literal in another form", "https://3221225985/c"],
		["an IPv6 literal", "https://[2001:db8::1]/c"],
		["localhost", "https://localhost/c"],
		["a name under localhost", "https://app.localhost/c"],
		["a trailing dot", "https://app.example./c"],
		["upper case in the host", "https://APP.example/c"],
		["upper case in the scheme", "HTTPS://app.example/c"],
		["the default port", "https://app.example:443/c"],
		["a host beyond ASCII", "https://äpp.example/c"],
		["a path the parser would encode", "https://app.example/ä{c}"],
		["a space", "https://app.example/a c"],
		["no URL", "app"],
	])("refuses %s", (_, given) => {
		expect(documentUrl(given)).toBeUndefined();
	});
});

describe("document record", () => {
	it("is a public client by none, its sections put for each owner", () => {
		expect(record({ client_uri: "https://app.example/" })).toEqual({
			id,
			kind: "public",
			method: "none",
			sections: {
				authorize: { "redirect-uris": ["https://app.example/cb"] },
				"client-allowance": {
					grants: ["authorization_code"],
					scopes: ["openid", "read"],
					audiences: ["https://api.example"],
				},
				consent: { name: "App", uri: "https://app.example/", host: "app.example" },
			},
		});
	});

	it("shows the id's host without its port", () => {
		const ported = "https://app.example:8443/c";
		const made = recordOf(new URL(ported), { ...doc, client_id: ported }, ceiling);
		expect("sections" in made && made.sections.consent).toMatchObject({ host: "app.example" });
	});

	it("keeps only the scopes within the ceiling, and none beyond", () => {
		expect(allowances({ scope: "read admin" })).toMatchObject({ scopes: ["read"] });
		expect(allowances({ scope: "" })).toMatchObject({ scopes: [] });
		expect(allowances({}, { scopes: [], audiences: [] })).toMatchObject({
			scopes: [],
			audiences: [],
		});
	});

	it("allows refresh only when the document names it, and no other grant", () => {
		expect(
			allowances({ grant_types: ["authorization_code", "refresh_token", "password"] }),
		).toMatchObject({ grants: ["authorization_code", "refresh_token"] });
	});

	it.each([
		["another client_id", { client_id: "https://app.example/other" }],
		["no client_id", { client_id: undefined }],
		["a client secret", { client_secret: "s" }],
		["a client secret's expiry", { client_secret_expires_at: 0 }],
		["a secret method", { token_endpoint_auth_method: "client_secret_basic" }],
		["a key method", { token_endpoint_auth_method: "private_key_jwt" }],
		["no redirect URIs", { redirect_uris: undefined }],
		["empty redirect URIs", { redirect_uris: [] }],
		["redirect URIs not strings", { redirect_uris: [1] }],
		["grant types without the code", { grant_types: ["refresh_token"] }],
		["grant types not strings", { grant_types: "authorization_code" }],
		["grant types holding a non-string", { grant_types: ["authorization_code", 1] }],
		["response types without code", { response_types: ["token"] }],
		["response types not strings", { response_types: "code" }],
		["no name", { client_name: undefined }],
		["a blank name", { client_name: " \t" }],
		["a name not a string", { client_name: 1 }],
		["a page not https", { client_uri: "http://app.example/" }],
		["a page not a URL", { client_uri: "app" }],
		["a page in a list", { client_uri: ["https://app.example/"] }],
		["a page with a tab the parser drops", { client_uri: "https://app.example/\tx" }],
		["a page with a space before it", { client_uri: " https://app.example/" }],
		["a page with a line break", { client_uri: "https://app.example/x\n" }],
		["a scope not a string", { scope: ["read"] }],
		["a scope not scope tokens", { scope: "read  write" }],
	])("is refused for %s", (_, fields) => {
		expect(record(fields)).toHaveProperty("refused");
	});

	it("takes the method none, and response types holding code", () => {
		const fields = { token_endpoint_auth_method: "none", response_types: ["code", "token"] };
		expect(record(fields)).not.toHaveProperty("refused");
	});
});
