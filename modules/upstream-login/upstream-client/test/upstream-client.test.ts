import { Unavailable } from "@mod/kernel";
import type { Outbound, OutboundRequest } from "@mod/outbound";
import { UpstreamRefused } from "@mod/upstreams";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { basicAuthorization } from "../src/basic.ts";
import {
	answerOf,
	authorizationUrl,
	clientSetting,
	credentialSetting,
	endpointSetting,
	endSessionUrl,
	guarded,
	refreshAnswerOf,
	scopeSetting,
	tokenAnswerOf,
	tokenPostOf,
} from "../src/contract.ts";

const start = {
	state: "s",
	nonce: "n",
	challenge: "c",
	challengeMethod: "S256" as const,
	redirectUri: "https://as.example/cb",
};
/** An answer `outbound` read as a JSON object of a 200. */
const object = (value: Record<string, unknown>) => ({ kind: "object", value }) as const;

describe("upstream-client", () => {
	it("builds the authorization request federation asks for, then a type's own parameters [oidc-core-3.1.2.1-x] [oidc-core-3.1.2.1-y] [rfc9700-2.1.1-f] [rfc9700-2.1.1-h] [rfc9700-2.1.2-a]", () => {
		const url = new URL(
			authorizationUrl(
				"https://idp.example/authorize?tenant=t",
				start,
				{ clientId: "cid", scopes: ["openid", "email"] },
				{ nonce: "n", state: "forged", code_challenge_method: "plain" },
			),
		);
		expect(`${url.origin}${url.pathname}`).toBe("https://idp.example/authorize");
		// A type's own parameters never replace federation's.
		expect(Object.fromEntries(url.searchParams)).toEqual({
			tenant: "t",
			response_type: "code",
			client_id: "cid",
			redirect_uri: "https://as.example/cb",
			scope: "openid email",
			state: "s",
			code_challenge: "c",
			code_challenge_method: "S256",
			nonce: "n",
		});
	});

	it("checks the endpoints and scopes an IdP's settings name", () => {
		expect(endpointSetting.safeParse("https://idp.example/token").success).toBe(true);
		expect(endpointSetting.safeParse("ftp://idp.example/token").success).toBe(false);
		expect(endpointSetting.parse("http://idp.example/")).toBe("http://idp.example/");
		for (const value of [
			"https://u:p@idp.example/token",
			"https://idp.example/token#x",
			"HTTPS://idp.example",
		]) {
			expect(endpointSetting.safeParse(value).success, value).toBe(false);
		}
		expect(scopeSetting.safeParse("read:user").success).toBe(true);
		for (const scope of ["", "a b", 'a"b', "a\\b"]) {
			expect(scopeSetting.safeParse(scope).success, scope).toBe(false);
		}
	});

	it("checks the client's ID and secret an IdP's settings name, as well-formed text that is not blank", () => {
		const both = { "client-id": "cid", "client-secret": "s3cr:et" };
		expect(clientSetting.parse(both)).toEqual(both);
		// Half a surrogate pair cannot be sent form-urlencoded: boot refuses it, not every exchange.
		for (const name of ["client-id", "client-secret"] as const) {
			for (const value of ["", " ", "\t\n", "\u00a0", "a\uD800", "\uDE00a", undefined]) {
				expect(clientSetting.safeParse({ ...both, [name]: value }).success, value).toBe(false);
			}
			expect(clientSetting.safeParse({ ...both, [name]: "a\uD83D\uDE00" }).success).toBe(true);
			// Only one that is blank throughout is refused; any other is taken as written.
			expect(clientSetting.parse({ ...both, [name]: " a b " })[name]).toBe(" a b ");
		}
	});

	it("lets only UpstreamRefused and Unavailable out of what a type runs, as they are", async () => {
		const refused = new UpstreamRefused();
		const down = new Unavailable("idp");
		await expect(guarded(async () => 7)).resolves.toBe(7);
		await expect(guarded(() => Promise.reject(refused))).rejects.toBe(refused);
		await expect(guarded(() => Promise.reject(down))).rejects.toBe(down);
		// A refusal another copy of upstreams in the bundle threw: another class, the same mark.
		const copied = Object.assign(new Error("upstream refused"), {
			[Symbol.for("@mod/upstreams.refused")]: true,
		});
		await expect(guarded(() => Promise.reject(copied))).rejects.toBe(copied);
		// Any other error refuses without its text.
		const others: Record<string, () => Promise<never>> = {
			"rejected later": () => Promise.reject(new TypeError("library text")),
			"thrown at once": () => {
				throw new Error("library text");
			},
		};
		for (const [label, run] of Object.entries(others)) {
			await expect(guarded(run), label).rejects.toSatisfy(
				(error) => UpstreamRefused.is(error) && !String(error).includes("library"),
			);
		}
	});

	it("reads an upstream's answer by a schema, refusing anything else, whatever the schema takes", () => {
		const id = z.looseObject({ id: z.number() });
		expect(answerOf(object({ id: 7, more: 1 }), id)).toEqual({ id: 7, more: 1 });
		expect(() => answerOf(object({ id: "7" }), id)).toThrow(UpstreamRefused);
		expect(() => answerOf({ kind: "other", status: 404 }, id)).toThrow(UpstreamRefused);
		// No JSON object of a 200 refuses, even where the schema would take nothing.
		expect(() => answerOf({ kind: "other", status: 404 }, z.unknown())).toThrow(UpstreamRefused);
	});

	const bare = { access_token: "at", token_type: "Bearer" };

	it("reads a token endpoint's answer into upstream tokens, keeping its id_token apart and passing over members it does not know [oidc-core-3.1.3.3-e]", () => {
		const full = {
			access_token: "at",
			token_type: "DPoP",
			refresh_token: "rt",
			expires_in: 0,
			scope: "openid  email",
			id_token: "idt",
			// Members of no profile this reads, of any type: none is a reason to refuse, none is kept.
			ext_expires_in: 3599,
			not_before_policy: { at: 0 },
			issued_token_type: ["x"],
		};
		expect(tokenAnswerOf(object(full), ["openid"])).toEqual({
			tokens: {
				accessToken: "at",
				tokenType: "DPoP",
				refreshToken: "rt",
				expiresInSeconds: 0,
				scope: ["openid", "email"],
			},
			idToken: "idt",
		});
	});

	it("takes a scope left out as the one asked, and refuses where the caller gives none", () => {
		expect(tokenAnswerOf(object(bare), ["openid"])).toEqual({
			tokens: { accessToken: "at", tokenType: "Bearer", scope: ["openid"] },
		});
		expect(tokenAnswerOf(object({ ...bare, scope: "" }))).toEqual({
			tokens: { accessToken: "at", tokenType: "Bearer", scope: [] },
		});
		expect(() => tokenAnswerOf(object(bare))).toThrow(UpstreamRefused);
	});

	it("refuses a token answer that does not hold", () => {
		const refused: Record<string, Record<string, unknown>> = {
			"no access token": { token_type: "Bearer" },
			"an empty access token": { ...bare, access_token: "" },
			"an empty token type": { ...bare, token_type: "" },
			"an empty refresh token": { ...bare, refresh_token: "" },
			"a negative lifetime": { ...bare, expires_in: -1 },
			"a lifetime in part seconds": { ...bare, expires_in: 1.5 },
			"a lifetime as text": { ...bare, expires_in: "300" },
			"a scope not text": { ...bare, scope: ["openid"] },
			"an empty id_token": { ...bare, id_token: "" },
		};
		for (const [label, value] of Object.entries(refused)) {
			expect(() => tokenAnswerOf(object(value), []), label).toThrow(UpstreamRefused);
		}
		expect(() => tokenAnswerOf({ kind: "other", status: 404 }, [])).toThrow(UpstreamRefused);
	});

	it("lets a type add its own settings to the client's, still refusing unknown keys", () => {
		const own = clientSetting.extend({ "team-id": credentialSetting.optional() });
		const both = { "client-id": "cid", "client-secret": "s" };
		expect(own.parse({ ...both, "team-id": "T1" })).toEqual({ ...both, "team-id": "T1" });
		expect(own.safeParse({ ...both, other: 1 }).success).toBe(false);
		for (const value of ["", "T\uD800"]) {
			expect(own.safeParse({ ...both, "team-id": value }).success, value).toBe(false);
		}
	});

	it("reads a refresh answer: tokens, a refused grant, a limit or an outage", () => {
		const answer = (status: number, json: unknown, headers: [string, string][] = []) => ({
			status,
			headers: new Map(headers),
			body: new TextEncoder().encode(JSON.stringify(json)),
		});
		const tokens = { access_token: "at", token_type: "Bearer", id_token: "unchecked" };
		expect(refreshAnswerOf(answer(200, tokens), ["openid"], "idp")).toEqual({
			kind: "refreshed",
			tokens: { accessToken: "at", tokenType: "Bearer", scope: ["openid"] },
		});
		expect(refreshAnswerOf(answer(400, { error: "invalid_grant" }), [], "idp")).toEqual({
			kind: "invalid_grant",
		});
		for (const error of [
			"interaction_required",
			"login_required",
			"consent_required",
			"account_selection_required",
		]) {
			expect(refreshAnswerOf(answer(400, { error }), [], "idp"), error).toEqual({
				kind: "interaction_required",
			});
		}
		const limited = (after?: string) =>
			refreshAnswerOf(
				answer(429, {}, after === undefined ? [] : [["retry-after", after]]),
				[],
				"idp",
			);
		expect(limited("7")).toEqual({ kind: "limited", retryAfterSeconds: 7 });
		expect(limited("0")).toEqual({ kind: "limited", retryAfterSeconds: 0 });
		// Only digits a number holds exactly are read; anything else, an empty value included, is none.
		const tooLong = "9".repeat(20);
		for (const after of [
			undefined,
			"",
			"-1",
			"1e3",
			"1.5",
			tooLong,
			"Wed, 21 Oct 2026 07:28:00 GMT",
		]) {
			expect(limited(after), String(after)).toEqual({ kind: "limited" });
		}
		for (const status of [500, 503]) {
			const thrown = (() => {
				try {
					refreshAnswerOf(answer(status, {}), [], "idp-x");
				} catch (error) {
					return error;
				}
			})();
			expect(thrown, String(status)).toBeInstanceOf(Unavailable);
			expect((thrown as Unavailable).what).toBe("idp-x");
		}
		const refused: Record<string, ReturnType<typeof answer>> = {
			"a 400 naming another error": answer(400, { error: "invalid_request" }),
			"a 400 that is no JSON object": answer(400, "invalid_grant"),
			"a 401": answer(401, { error: "invalid_grant" }),
			"a 200 without tokens": answer(200, {}),
		};
		for (const [label, value] of Object.entries(refused)) {
			expect(() => refreshAnswerOf(value, [], "idp"), label).toThrow(UpstreamRefused);
		}
	});

	it("builds the Basic client authentication from the form-urlencoded ID and secret", () => {
		const basic = (pair: string) => `Basic ${Buffer.from(pair).toString("base64")}`;
		expect(basicAuthorization("cid", "s3cr:et")).toBe(basic("cid:s3cr%3Aet"));
		// RFC 6749 Appendix B's example.
		expect(basicAuthorization("cid", " %&+£€")).toBe(basic("cid:+%25%26%2B%C2%A3%E2%82%AC"));
		// A space is `+`; of the marks, only `*` stays as it is.
		const encoded: Record<string, string> = {
			" ": "+",
			"!": "%21",
			"'": "%27",
			"(": "%28",
			")": "%29",
			"~": "%7E",
			"*": "*",
			"/": "%2F",
		};
		for (const [raw, form] of Object.entries(encoded)) {
			expect(basicAuthorization(`a${raw}b`, raw), raw).toBe(basic(`a${form}b:${form}`));
		}
	});

	it("builds an end-session URL with each parameter given, then a type's own", () => {
		const at = { idTokenHint: "h", postLogoutRedirectUri: "https://app.example/bye", state: "st" };
		expect(endSessionUrl("https://idp.example/logout?x=1", at, { ui_locales: "ja" })).toBe(
			"https://idp.example/logout?x=1&id_token_hint=h&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fbye&state=st&ui_locales=ja",
		);
		expect(endSessionUrl("https://idp.example/logout", { idTokenHint: "", state: "st" })).toBe(
			"https://idp.example/logout?state=st",
		);
		expect(endSessionUrl("https://idp.example/logout", {})).toBe("https://idp.example/logout");
	});

	it("never lets a type's own parameter replace or place one the protocol fixes", () => {
		const own = {
			id_token_hint: "other",
			post_logout_redirect_uri: "https://elsewhere.example/bye",
			state: "other",
			client_id: "other",
			ui_locales: "ja",
		};
		const at = {
			idTokenHint: "h",
			postLogoutRedirectUri: "https://app.example/bye",
			state: "st",
			clientId: "cid",
		};
		const query = (url: string) => Object.fromEntries(new URL(url).searchParams);
		expect(query(endSessionUrl("https://idp.example/logout", at, own))).toEqual({
			id_token_hint: "h",
			post_logout_redirect_uri: "https://app.example/bye",
			state: "st",
			client_id: "cid",
			ui_locales: "ja",
		});
		// Where none is given, the type's own of that name is dropped too.
		expect(query(endSessionUrl("https://idp.example/logout", {}, own))).toEqual({
			ui_locales: "ja",
		});
	});

	it("places a given client ID in the end-session URL", () => {
		expect(endSessionUrl("https://idp.example/logout", { state: "st", clientId: "cid" })).toBe(
			"https://idp.example/logout?state=st&client_id=cid",
		);
	});
});

describe("a token post", () => {
	/** An outbound that keeps every request it is asked for and answers an empty JSON object. */
	const recorded = () => {
		const asked: { url: string; request: OutboundRequest | undefined; narrower: unknown }[] = [];
		const outbound: Outbound = {
			fetch: async (url, request, narrower) => {
				asked.push({ url, request, narrower });
				return { status: 200, headers: new Map(), body: new TextEncoder().encode("{}") };
			},
		};
		return { outbound, asked };
	};
	const hosts = { hosts: ["idp.example"] };

	it("sends the secret as HTTP Basic, the grant alone in the form", async () => {
		const { outbound, asked } = recorded();
		const post = tokenPostOf(
			outbound,
			"https://idp.example/token",
			{ id: "cid", auth: "basic", secret: async () => "s3cr:et" },
			hosts,
		);
		await post({ grant_type: "refresh_token", refresh_token: "r" });
		expect(asked).toEqual([
			{
				url: "https://idp.example/token",
				narrower: hosts,
				request: {
					method: "POST",
					headers: {
						"content-type": "application/x-www-form-urlencoded",
						accept: "application/json",
					},
					body: "grant_type=refresh_token&refresh_token=r",
					credential: basicAuthorization("cid", "s3cr:et"),
				},
			},
		]);
	});

	it("sends the ID and secret in the form after the grant, asking for the secret at each post", async () => {
		const { outbound, asked } = recorded();
		let signed = 0;
		const post = tokenPostOf(
			outbound,
			"https://idp.example/token",
			{ id: "cid", auth: "form", secret: async () => `jwt-${++signed}` },
			hosts,
		);
		await post({ grant_type: "authorization_code", code: "c" });
		await post({ grant_type: "refresh_token", refresh_token: "r" });
		expect(asked.map((a) => a.request?.body)).toEqual([
			"grant_type=authorization_code&code=c&client_id=cid&client_secret=jwt-1",
			"grant_type=refresh_token&refresh_token=r&client_id=cid&client_secret=jwt-2",
		]);
		expect(asked.every((a) => a.request?.credential === undefined)).toBe(true);
	});
});
