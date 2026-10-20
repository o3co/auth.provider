import { clientSecret } from "@mod/clients/testing";
import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { senderBindings } from "@mod/sender-binding";
import { type AccessCondition, accessConditions } from "@mod/tokens";
import { describe, expect, it } from "vitest";
import { section } from "../src/section.ts";
import { serve } from "./serve.ts";

describe("introspection", () => {
	it("tells a resource server sharing the audience about an active token", async () => {
		const s = await serve();
		const answer = await s.post("/oauth/introspect", "api", { token: await s.issue() });
		expect(answer.status).toBe(200);
		expect(answer.headers.get("cache-control")).toBe("no-store");
		expect(answer.json).toMatchObject({
			active: true,
			client_id: "app",
			sub: "app",
			aud: "https://api",
			scope: "read",
		});
	});

	it("tells a resource server how an access token is bound", async () => {
		/** The binding kind the bound token is issued with, so tokens reads its member back. */
		const keyed = defineModule({ name: "keyed-binding" }, (m) => [
			m
				.contribute(senderBindings)
				.by(() => ({ member: "key", tokenType: "Keyed", read: async () => ({ kind: "absent" }) })),
		]);
		const s = await serve({ extra: [keyed] });
		const binding = { member: "key", confirmation: "k1", tokenType: "Keyed" };
		const bound = await s.post("/oauth/introspect", "app", { token: await s.issue({ binding }) });
		expect(bound.json).toMatchObject({ active: true, token_type: "Keyed", cnf: { key: "k1" } });
		const bearer = await s.post("/oauth/introspect", "app", { token: await s.issue() });
		expect(bearer.json).toMatchObject({ active: true, token_type: "Bearer" });
		expect(bearer.json.cnf).toBeUndefined();
	});

	it("answers inactive for tokens the caller may not see, broken tokens and nothing more", async () => {
		const s = await serve();
		const token = await s.issue();
		const inactive = { active: false };
		const answer = async (as: string, sent: string) =>
			(await s.post("/oauth/introspect", as, { token: sent })).json;
		expect(await answer("other", token), "an audience the caller may not see").toEqual(inactive);
		expect(await answer("api", `${token}x`), "a token altered").toEqual(inactive);
		expect(await answer("api", "garbage"), "no token at all").toEqual(inactive);
	});

	it("refuses public clients, missing tokens, repeated parameters and bad client credentials, recording only the credentials' refusal", async () => {
		const s = await serve();
		const token = await s.issue();
		expect((await s.post("/oauth/introspect", undefined, { token, client_id: "pub" })).status).toBe(
			401,
		);
		expect((await s.post("/oauth/introspect", "api", {})).error).toBe("invalid_request");
		for (const repeated of [
			[["token", token]],
			[
				["token_type_hint", "access_token"],
				["token_type_hint", "access_token"],
			],
		] as [string, string][][]) {
			const answer = await s.post("/oauth/introspect", "api", [["token", token], ...repeated]);
			expect([answer.status, answer.error]).toEqual([400, "invalid_request"]);
		}
		const wrong = { token, client_id: "api", client_secret: `${clientSecret("api")}x` };
		expect((await s.post("/oauth/introspect", undefined, wrong)).status).toBe(401);
		expect(s.events).toEqual([
			{
				kind: "client.authentication.failure",
				at: expect.any(Number),
				attributes: { source: "127.0.0.1", reason: "bad_credentials" },
			},
		]);
	});

	it("answers 503 when a condition on access tokens cannot tell, never inactive, recording and warning so", async () => {
		const down = unavailableSwitch<AccessCondition>();
		const condition = defineModule({ name: "condition" }, (m) => [
			m
				.contribute(accessConditions)
				.by(() => down.wrap({ name: "test", holds: async () => "holds" as const })),
		]);
		const s = await serve({ extra: [condition] });
		const token = await s.issue();
		expect(await s.active(token)).toBe(true);
		down.unavailable("holds");
		const answer = await s.post("/oauth/introspect", "app", { token });
		expect([answer.status, answer.error]).toEqual([503, "temporarily_unavailable"]);
		expect(s.events).toEqual([
			{
				kind: "introspection.unavailable",
				at: expect.any(Number),
				attributes: { source: "127.0.0.1" },
			},
		]);
		expect(s.warnings()).toEqual([
			["http.unavailable", { what: "test", route: "/oauth/introspect" }],
		]);
	});
});

describe("rate limit", () => {
	it("limits requests per source on each route apart, before any client is authenticated", async () => {
		const s = await serve({ limit: { requests: 2, window: "1m" } });
		const wrong = { token: await s.issue(), client_id: "api", client_secret: "wrong" };
		for (let i = 0; i < 2; i++) {
			expect((await s.post("/oauth/introspect", undefined, wrong)).status).toBe(401);
		}
		const limited = await s.post("/oauth/introspect", undefined, wrong);
		expect([limited.status, limited.headers.get("retry-after"), limited.json]).toEqual([
			429,
			"60",
			{ error: "rate_limited" },
		]);
		for (let i = 0; i < 2; i++) {
			expect((await s.post("/oauth/revoke", undefined, wrong)).status).toBe(401);
		}
		expect((await s.post("/oauth/revoke", undefined, wrong)).status).toBe(429);
	});
});

it("counts 60 requests per minute unless set, taking the window only with its unit, in whole seconds", () => {
	expect(section.parse({})).toEqual({ requests: 60, window: 60 });
	const takes = (window: unknown) => section.safeParse({ window }).success;
	expect(["1s", "1d", "86401s", 60, "1500ms"].map(takes)).toEqual([
		true,
		true,
		false,
		false,
		false,
	]);
});
