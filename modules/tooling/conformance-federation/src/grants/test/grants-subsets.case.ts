import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type GrantsTarget, grantsTarget, scopes } from "./grants.ts";

let t: GrantsTarget;
beforeAll(async () => {
	t = await grantsTarget({
		connections: [
			{ name: "calendar", idp: "corp", scopes, maxAccessTokenSeconds: 3600, scopeSubsets: true },
		],
	});
});
afterAll(async () => {
	await t?.stop();
});

describe("federation grants: a connection that takes subsets of its scopes", () => {
	it("lodges an intent for fewer of the scopes, asks the upstream for those alone, and hands a token for them", async () => {
		const subset = "openid offline_access";
		const lodged = await t.lodge({ scope: subset });
		expect(lodged.status).toBe(201);
		const b = await t.loggedIn();
		const { challenge } = await t.open(b, lodged.body.connect_uri);
		const accepted = await t.answer(b, { challenge, decision: "accept" });
		expect(new URL(accepted.location).searchParams.get("scope")).toBe(subset);
		const query = t.corp.authorize(accepted.location, {
			subject: "u-alice",
			tokens: { accessToken: "up-subset", scope: subset },
		});
		const done = await t.callback(b, query);
		expect(t.returned(done).get("error")).toBeNull();
		const token = await t.grantCall(String(lodged.body.grant_id), "token");
		expect([token.status, token.body.access_token, token.body.scope]).toEqual([
			200,
			"up-subset",
			subset,
		]);
	});

	it("still refuses a subset without openid or offline_access, and one beyond the connection's scopes", async () => {
		for (const scope of [
			"offline_access calendar.read",
			"openid calendar.read",
			"openid offline_access calendar.write",
		]) {
			const lodged = await t.lodge({ scope });
			expect([scope, lodged.status, lodged.body.error]).toEqual([scope, 400, "invalid_scope"]);
		}
	});
});
