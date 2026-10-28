import { allowancesFor } from "@mod/client-allowance/testing";
import type { Client, Section } from "@mod/clients";
import { describe, expect, it } from "vitest";
import { checkRequest, checkScope } from "../checks.ts";

const sections: Record<string, unknown> = allowancesFor({
	grants: ["authorization_code"],
	scopes: ["openid", "read"],
});
const app: Client = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	registered: true,
	section: <T>(section: Section<T>) =>
		(section.schema["~standard"].validate(sections[section.name]) as { value: T }).value,
};

/** An OpenID Connect request's parameters, with these added and those named in `left` left out. */
const oidc = (extra: Record<string, string> = {}, ...left: string[]) => {
	const params = new Map(
		Object.entries({
			response_type: "code",
			client_id: "app",
			scope: "openid read",
			code_challenge: "A".repeat(43),
			code_challenge_method: "S256",
			...extra,
		}),
	);
	for (const name of left) params.delete(name);
	return params;
};
const checked = (params: Map<string, string>) =>
	checkRequest(app, (name) => params.get(name), params);
/** The error and description of a refusal, or the kind of what it decided otherwise. */
const outcome = (params: Map<string, string>) => {
	const decided = checked(params);
	return decided.kind === "refuse" ? [decided.error, decided.description] : [decided.kind];
};

describe("checks: an OpenID Connect request's form", () => {
	it("refuses one without a response type as invalid_request, and any type but code as unsupported_response_type, a token in the URL among them [oidc-core-3.1.2.1-c] [oidc-core-3.1.2.2-c] [rfc6750-5.3-d] [oidc-core-16.4-a]", () => {
		expect(outcome(oidc({}, "response_type"))).toEqual([
			"invalid_request",
			"response_type is required",
		]);
		expect(outcome(oidc({ response_type: "" }))).toEqual([
			"invalid_request",
			"response_type is required",
		]);
		for (const response_type of ["token", "id_token", "code id_token", "code token"]) {
			expect(outcome(oidc({ response_type }))[0], response_type).toBe("unsupported_response_type");
		}
	});

	it("refuses a request object by URI as request_uri_not_supported [oidc-core-6.2-a]", () => {
		expect(outcome(oidc({ request_uri: "https://app.example/r" }))[0]).toBe(
			"request_uri_not_supported",
		);
	});

	it("takes any display, ui_locales or claims_locales without an error [oidc-core-15.1-c] [oidc-core-15.1-d] [oidc-core-3.1.2.1-t] [oidc-core-5.2-e]", () => {
		for (const extra of [
			{ display: "popup" },
			{ display: "no-such-display" },
			{ ui_locales: "tlh-Latn xx-YY" },
			{ claims_locales: "tlh xx-YY" },
			{ display: "touch", ui_locales: "fr-CA fr en", claims_locales: "en" },
		]) {
			expect(outcome(oidc(extra)), JSON.stringify(extra)).toEqual(["checked"]);
		}
	});

	it("checks each OAuth parameter it carries by OAuth's rules, and those OpenID Connect adds by its own [oidc-core-3.1.2.2-b] [oidc-core-3.1.2.2-c]", () => {
		for (const [extra, left] of [
			[{}, "code_challenge"],
			[{}, "code_challenge_method"],
			[{ code_challenge_method: "plain" }, ""],
			[{ code_challenge: "A".repeat(42) }, ""],
			[{ response_mode: "fragment" }, ""],
			[{ nonce: "n".repeat(257) }, ""],
			[{ prompt: "maybe" }, ""],
			[{ prompt: "none login" }, ""],
			[{ max_age: "-1" }, ""],
		] as const) {
			expect(outcome(oidc(extra, left))[0], JSON.stringify([extra, left])).toBe("invalid_request");
		}
		expect(
			checked(oidc({ nonce: "n".repeat(256), prompt: "login consent", max_age: "60" })),
		).toEqual({
			kind: "checked",
			challenge: "A".repeat(43),
			nonce: "n".repeat(256),
			prompt: new Set(["login", "consent"]),
			maxAgeMs: 60_000,
		});
	});

	it("says a code challenge by S256 is required, where it refuses a request without one [rfc7636-4.4.1-b]", () => {
		for (const sent of [oidc({}, "code_challenge"), oidc({ code_challenge: "" })]) {
			expect(outcome(sent)).toEqual(["invalid_request", "PKCE with S256 is required"]);
		}
	});

	it("says the method is not supported, where it refuses plain, another or one left out, which is plain [rfc7636-4.4.1-d]", () => {
		for (const sent of [
			oidc({ code_challenge_method: "plain" }),
			oidc({ code_challenge_method: "S512" }),
			oidc({}, "code_challenge_method"),
		]) {
			expect(outcome(sent)).toEqual([
				"invalid_request",
				"code_challenge_method is not supported: only S256",
			]);
		}
	});

	it("says the challenge is malformed, where S256 is asked of one that is not 43 base64url characters", () => {
		for (const code_challenge of ["A".repeat(42), "A".repeat(44), `${"A".repeat(42)}+`]) {
			expect(outcome(oidc({ code_challenge }))).toEqual([
				"invalid_request",
				"code_challenge is malformed",
			]);
		}
	});
});

describe("checks: offline_access", () => {
	const scopeOf = (scope: string, openidRequired = false) => {
		const decided = checkScope(app, scope, "https://as.example", openidRequired);
		if (decided.kind === "allowed") return decided.scope;
		return decided.kind === "refuse" ? [decided.error, decided.description] : [decided.kind];
	};

	it("drops offline_access from a request rather than refusing it, as no offline access is offered and so nothing permits it [oidc-core-11-c] [oidc-core-11-d]", () => {
		expect(scopeOf("openid offline_access read")).toEqual(["openid", "read"]);
		expect(scopeOf("offline_access openid", true)).toEqual(["openid"]);
	});

	it("drops offline_access from a request without openid too, the word having the one meaning", () => {
		expect(scopeOf("offline_access read")).toEqual(["read"]);
	});

	it("refuses a request that names offline_access alone as invalid_scope, never giving it the client's default", () => {
		expect(scopeOf("offline_access")).toEqual(["invalid_scope", "offline_access is not offered"]);
		expect(scopeOf("offline_access offline_access")).toEqual([
			"invalid_scope",
			"offline_access is not offered",
		]);
	});
});
