import { defineModule, type Module } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import { type RevocableKind, type Revoked, revocableKinds } from "../src/contract.ts";
import { type Form, serve } from "./serve.ts";

describe("revocation", () => {
	/** A contributed kind answering each token from `answers` (else unknown), noting each try in `tried`. */
	const kind = (hint: string, answers: Record<string, Revoked>, tried: string[] = []): Module =>
		defineModule({ name: `kind-${hint}`, takes: [] }, (m) => [
			m.contribute(revocableKinds).by(
				(): RevocableKind => ({
					hint,
					revoke: async (token, client) => {
						tried.push(`${hint}:${token}:${client.id}`);
						return answers[token] ?? "unknown";
					},
				}),
			),
		]);

	it("lets the issuing client revoke its access token, with an empty answer that is not cached [rfc7009-2-b] [rfc7662-4-d]", async () => {
		const s = await serve();
		const token = await s.issue();
		const answer = await s.post("/oauth/revoke", "app", { token });
		expect(answer.status).toBe(200);
		expect(answer.text).toBe("");
		expect(answer.headers.get("cache-control")).toBe("no-store");
		expect(await s.active(token)).toBe(false);
		expect((await s.post("/oauth/revoke", "app", { token })).status).toBe(200);
	});

	it("answers another client the same, and leaves the token alone", async () => {
		const s = await serve();
		const token = await s.issue();
		const answer = await s.post("/oauth/revoke", "other", { token });
		expect([answer.status, answer.text]).toEqual([200, ""]);
		expect(await s.active(token)).toBe(true);
	});

	it("answers 200 for a token it does not know, and takes the hint only as a hint [rfc7009-2.1-b]", async () => {
		const s = await serve();
		expect((await s.post("/oauth/revoke", "app", { token: "not-a-token" })).status).toBe(200);
		const refreshLike = { token: "rt-0123456789abcdef", token_type_hint: "refresh_token" };
		expect((await s.post("/oauth/revoke", "app", refreshLike)).status).toBe(200);
		const token = await s.issue();
		const hinted = await s.post("/oauth/revoke", "app", {
			token,
			token_type_hint: "refresh_token",
		});
		expect(hinted.status).toBe(200);
		expect(await s.active(token)).toBe(false);
		const other = await s.issue();
		const unknownHint = await s.post("/oauth/revoke", "app", {
			token: other,
			token_type_hint: "id_token",
		});
		expect(unknownHint.status).toBe(200);
		expect(await s.active(other)).toBe(false);
	});

	it("tries each kind once at most for a request, whatever hint it sends [rfc7009-5-b]", async () => {
		const tried: string[] = [];
		const s = await serve({ extra: [kind("refresh_token", {}, tried)] });
		const hints = [
			"refresh_token",
			"access_token",
			"id_token",
			"x".repeat(4000),
			"",
			"refresh_token ",
		];
		for (const token_type_hint of hints) {
			const before = tried.length;
			const answer = await s.post("/oauth/revoke", "app", { token: "unknown", token_type_hint });
			expect(answer.status, token_type_hint).toBe(200);
			expect(tried.length - before, token_type_hint).toBe(1);
		}
	});

	it("tries a contributed kind first when hinted, and after access tokens otherwise", async () => {
		const tried: string[] = [];
		const s = await serve({ extra: [kind("refresh_token", { mine: "done" }, tried)] });
		await s.post("/oauth/revoke", "app", { token: "mine", token_type_hint: "refresh_token" });
		expect(tried).toEqual(["refresh_token:mine:app"]);
		const access = await s.issue();
		await s.post("/oauth/revoke", "app", { token: access });
		expect(tried, "access tokens answer first without the hint").toEqual([
			"refresh_token:mine:app",
		]);
		expect(await s.active(access)).toBe(false);
	});

	it("revokes an access token hinted as another kind, after that kind does not know it [rfc7009-2.1-b]", async () => {
		const tried: string[] = [];
		const s = await serve({ extra: [kind("refresh_token", {}, tried)] });
		const access = await s.issue();
		await s.post("/oauth/revoke", "app", { token: access, token_type_hint: "refresh_token" });
		expect(tried).toEqual([`refresh_token:${access}:app`]);
		expect(await s.active(access)).toBe(false);
	});

	it("says when a contributed kind cannot be revoked", async () => {
		const s = await serve({ extra: [kind("refresh_token", { stuck: "unsupported" })] });
		const answer = await s.post("/oauth/revoke", "app", { token: "stuck" });
		expect([answer.status, answer.error]).toEqual([400, "unsupported_token_type"]);
	});

	it("refuses at boot a contribution for access tokens", async () => {
		await expect(serve({ extra: [kind("access_token", {})] })).rejects.toMatchObject({
			refusals: expect.arrayContaining([expect.objectContaining({ where: "token-control" })]),
		});
	});

	it("records a revocation it wrote for the issuing client, and nothing for another client's token, nor for a contributed kind's done", async () => {
		const alwaysDone = kind("refresh_token", { "not-a-token": "done" });
		const s = await serve({ extra: [alwaysDone] });
		const token = await s.issue();
		await s.post("/oauth/revoke", "other", { token });
		// Unknown as an access token, then done by the contributed kind.
		await s.post("/oauth/revoke", "app", { token: "not-a-token" });
		expect(s.events).toEqual([]);
		await s.post("/oauth/revoke", "app", { token });
		expect(s.events).toEqual([
			{
				kind: "token.revoked",
				at: expect.any(Number),
				attributes: { client: "app", source: "127.0.0.1", token_type: "access_token" },
			},
		]);
		expect(JSON.stringify(s.events)).not.toContain(token);
	});

	it("records a contributed kind's revocation when it answers written, under its hint", async () => {
		const s = await serve({ extra: [kind("refresh_token", { mine: "written" })] });
		expect((await s.post("/oauth/revoke", "app", { token: "mine" })).status).toBe(200);
		expect(s.events).toEqual([
			{
				kind: "token.revoked",
				at: expect.any(Number),
				attributes: { client: "app", source: "127.0.0.1", token_type: "refresh_token" },
			},
		]);
	});

	it("answers 503 to a sender behind a trusted proxy before revoking anything, so no event is recorded", async () => {
		const s = await serve({ http: { "trusted-proxies": ["127.0.0.1"] } });
		const token = await s.issue();
		expect([(await s.post("/oauth/revoke", "app", { token })).status, s.events]).toEqual([503, []]);
	});

	it("refuses a request without a token, a repeated parameter, and an unknown client, recording only the client's refusal [rfc7009-2.1-a]", async () => {
		const s = await serve();
		const error = async (form: Form, as = "app") => {
			const answer = await s.post("/oauth/revoke", as, form);
			return [answer.status, answer.error];
		};
		expect(await error({})).toEqual([400, "invalid_request"]);
		expect(await error({ token: "t" }, "nobody")).toEqual([401, "invalid_client"]);
		expect(
			await error([
				["token", "t"],
				["token", "u"],
			]),
		).toEqual([400, "invalid_request"]);
		expect(
			await error([
				["token", "t"],
				["token_type_hint", "access_token"],
				["token_type_hint", "access_token"],
			]),
		).toEqual([400, "invalid_request"]);
		expect(s.events).toEqual([
			{
				kind: "client.authentication.failure",
				at: expect.any(Number),
				attributes: { source: "127.0.0.1", reason: "unknown_client" },
			},
		]);
	});

	it("tells the issuing client that access tokens cannot be revoked where that was declared", async () => {
		const s = await serve({ revocation: "unsupported" });
		const token = await s.issue();
		const answer = await s.post("/oauth/revoke", "app", { token });
		expect([answer.status, answer.error]).toEqual([400, "unsupported_token_type"]);
		expect(await s.active(token)).toBe(true);
		expect((await s.post("/oauth/revoke", "other", { token })).status).toBe(200);
	});

	it("answers 503 when a revocation cannot be made, and leaves the token as it was", async () => {
		const s = await serve();
		const token = await s.issue();
		s.down.unavailable("revokeAccess");
		const answer = await s.post("/oauth/revoke", "app", { token });
		expect([answer.status, answer.error]).toEqual([503, "temporarily_unavailable"]);
		expect(s.warnings()).toEqual([
			["http.unavailable", { what: "tokens", route: "/oauth/revoke" }],
		]);
		s.down.restore();
		expect(await s.active(token)).toBe(true);
	});
});

it("lets a listed origin's page revoke its token, sending its credentials and reading the challenge and the wait [oidc-discovery-3-aj]", async () => {
	const { base } = await serve({ http: { "cors-origins": ["https://app.example"] } });
	const origin = "https://app.example";
	const asked = await fetch(`${base}/oauth/revoke`, {
		method: "OPTIONS",
		headers: {
			origin,
			"access-control-request-method": "POST",
			"access-control-request-headers": "authorization, content-type",
		},
	});
	expect(asked.headers.get("access-control-allow-origin")).toBe(origin);
	expect(asked.headers.get("access-control-allow-headers")?.split(/,\s*/)).toEqual([
		"authorization",
		"content-type",
	]);
	const revoked = await fetch(`${base}/oauth/revoke`, {
		method: "POST",
		headers: { origin, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ client_id: "pub", token: "unknown" }),
	});
	expect(revoked.status).toBe(200);
	expect(revoked.headers.get("access-control-allow-origin")).toBe(origin);
	expect(revoked.headers.get("access-control-expose-headers")?.split(/,\s*/)).toEqual([
		"www-authenticate",
		"retry-after",
	]);
	// Introspection is between servers: no page is let through.
	const introspect = await fetch(`${base}/oauth/introspect`, {
		method: "OPTIONS",
		headers: { origin, "access-control-request-method": "POST" },
	});
	expect(introspect.headers.get("access-control-allow-origin")).toBeNull();
});
