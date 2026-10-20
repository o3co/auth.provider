import { areaTarget } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { back, type GrantsTarget, grantsTarget, origin, page, scopes } from "./grants.ts";

let t: GrantsTarget;
beforeAll(async () => {
	t = await grantsTarget();
});
afterAll(async () => {
	await t?.stop();
});

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** A grant whose upstream token lives four seconds, past half of it, so the next request refreshes. */
async function due() {
	const grant = await t.connected({ expiresIn: 4 });
	await pause(2100);
	return grant;
}

describe("federation grants: connecting and using a grant", () => {
	it("lodges an intent, connects it through the user and the upstream, and hands the client the token", async () => {
		const lodged = await t.lodge();
		expect(lodged.status).toBe(201);
		expect(lodged.body).toMatchObject({ status: "pending", connect_expires_in: 600 });
		const id = String(lodged.body.grant_id);
		const b = await t.loggedIn();
		const { opened, challenge } = await t.open(b, lodged.body.connect_uri);
		expect(opened.status).toBe(303);
		expect(opened.location.startsWith(`${page}?challenge=`)).toBe(true);
		const accepted = await t.answer(b, { challenge, decision: "accept" });
		expect(accepted.status).toBe(303);
		const asked = new URL(accepted.location).searchParams;
		expect(asked.get("redirect_uri")).toBe(`${origin}/session/federation-grants/callback/calendar`);
		expect(asked.get("scope")?.split(" ")).toEqual(scopes);
		const query = t.corp.authorize(accepted.location, {
			subject: "u-alice",
			tokens: { accessToken: "up-grant", scope: scopes.join(" ") },
		});
		const done = await t.callback(b, query);
		expect(done.status).toBe(303);
		expect(done.location).toBe(`${back}?grant_id=${id}&state=st-1`);

		const token = await t.grantCall(id, "token");
		expect(token.status).toBe(200);
		expect(token.body).toMatchObject({ access_token: "up-grant", scope: scopes.join(" ") });
		expect(String(token.body.token_type).toLowerCase()).toBe("bearer");
		expect(token.body.expires_in).toBeGreaterThan(290);
		const status = await t.grantCall(id, "status");
		expect(status.body).toMatchObject({
			grant_id: id,
			status: "active",
			sub: "alice",
			connection: "calendar",
		});
	});

	it("ends a grant its client revokes: 204, again 204, then 410 and revoked", async () => {
		const { id } = await t.connected();
		expect((await t.grantCall(id, "revoke")).status).toBe(204);
		expect((await t.grantCall(id, "revoke")).status).toBe(204);
		const token = await t.grantCall(id, "token");
		expect([token.status, token.body.error]).toEqual([410, "grant_revoked"]);
		expect((await t.grantCall(id, "status")).body.status).toBe("revoked");
	});

	it("sends a refused question back with access_denied, the client's state and the grant", async () => {
		const lodged = await t.lodge({ state: "st-deny" });
		const b = await t.loggedIn();
		const { challenge } = await t.open(b, lodged.body.connect_uri);
		const denied = await t.answer(b, { challenge, decision: "deny" });
		const query = t.returned(denied);
		expect([query.get("error"), query.get("state"), query.get("grant_id")]).toEqual([
			"access_denied",
			"st-deny",
			lodged.body.grant_id,
		]);
		const pending = await t.grantCall(String(lodged.body.grant_id), "token");
		expect([pending.status, pending.body.error]).toEqual([400, "authorization_pending"]);
	});

	it("renews a grant through a new connection, and the grant serves throughout", async () => {
		const { id, b } = await t.connected();
		const renewed = await t.connected({ accessToken: "up-renewed" }, { renew: id, b });
		expect(renewed.lodged.status).toBe(201);
		expect(renewed.lodged.body).toMatchObject({ grant_id: id, status: "active" });
		expect(renewed.done.location).toBe(`${back}?grant_id=${id}&state=st-1`);
		expect((await t.grantCall(id, "token")).body.access_token).toBe("up-renewed");
	});
});

describe("federation grants: refusals", () => {
	it("answers another client's, another subject's and an unknown grant alike, on every grant route", async () => {
		const { id } = await t.connected();
		for (const step of ["token", "status", "revoke", "reauthorize"]) {
			const fields = step === "reauthorize" ? { redirect_uri: back, state: "r" } : {};
			const answers = [
				await t.grantCall(id, step, fields, "other-worker"),
				await t.grantCall(id, step, { ...fields, sub: "bob" }),
				await t.grantCall("no-such-grant", step, fields),
			];
			for (const answer of answers) {
				expect([answer.status, answer.text]).toEqual([answers[0]?.status, answers[0]?.text]);
			}
			expect([answers[0]?.status, answers[0]?.body.error]).toEqual([404, "grant_not_found"]);
		}
		expect((await t.grantCall(id, "token")).status).toBe(200);
	});

	it("refuses the answer to the question without evidence of the provider's origin", async () => {
		const lodged = await t.lodge();
		const b = await t.loggedIn();
		const { challenge } = await t.open(b, lodged.body.connect_uri);
		expect(
			(await t.answer(b, { challenge, decision: "accept" }, { origin: "https://evil.example" }))
				.status,
		).toBe(403);
		expect((await t.answer(b, { challenge, decision: "accept" }, {})).status).toBe(403);
		// Nothing was spent: the page's own answer still goes through.
		expect((await t.answer(b, { challenge, decision: "accept" })).status).toBe(303);
	});

	it("refuses the link to a browser logged in as another user", async () => {
		const lodged = await t.lodge();
		const bob = await t.loggedIn("u-bob");
		expect((await t.open(bob, lodged.body.connect_uri)).opened.status).toBe(403);
	});

	// Ours ties a connection's round trip to the browser that began it, as well as to its session.
	it.skipIf(areaTarget().differs("grants-round-trip-tied-to-browser"))(
		"takes nothing for a callback that comes back in another browser, leaving the round trip to its own",
		async () => {
			const lodged = await t.lodge();
			const first = await t.loggedIn();
			const { challenge } = await t.open(first, lodged.body.connect_uri);
			const accepted = await t.answer(first, { challenge, decision: "accept" });
			const query = t.corp.authorize(accepted.location, {
				subject: "u-alice",
				tokens: { scope: scopes.join(" ") },
			});
			expect((await t.callback(await t.loggedIn(), query)).status).toBe(400);
			// A failure is sent back by 303 too: the connection is made, with no error, and the grant serves.
			const done = await t.callback(first, query);
			expect(done.status).toBe(303);
			expect(t.returned(done).get("error")).toBeNull();
			const id = String(lodged.body.grant_id);
			expect(t.returned(done).get("grant_id")).toBe(id);
			expect((await t.grantCall(id, "status")).body.status).toBe("active");
		},
	);

	it("holds no token that is not a bearer, nor one without a refresh token, nor one wider than shown", async () => {
		for (const [tokens, error] of [
			[{ tokenType: "DPoP" }, "upstream_token_ineligible"],
			[{ refresh: false }, "refresh_token_absent"],
			[{ scope: `${scopes.join(" ")} calendar.write` }, "scope_exceeded"],
		] as const) {
			const { done, id } = await t.connected(tokens);
			expect(t.returned(done).get("error")).toBe(error);
			expect((await t.grantCall(id, "status")).body.status).toBe("pending");
		}
	});

	it("refuses a scope wider than the connection's, at lodging and at the token", async () => {
		const lodged = await t.lodge({ scope: "openid offline_access calendar.write" });
		expect([lodged.status, lodged.body.error]).toEqual([400, "invalid_scope"]);
		const { id } = await t.connected();
		const token = await t.grantCall(id, "token", { scope: "openid calendar.write" });
		expect([token.status, token.body.error]).toEqual([400, "invalid_scope"]);
	});

	it("refuses a lodging that asks fewer of the scopes than the connection has, where the connection takes no subsets", async () => {
		const lodged = await t.lodge({ scope: "openid offline_access" });
		expect([lodged.status, lodged.body.error]).toEqual([400, "invalid_scope"]);
	});

	it.skipIf(areaTarget().differs("grants-pending-push-out"))(
		"pushes out the oldest of a client's pending intents for one user past the cap, whose link then fails",
		async () => {
			const first = await t.lodge({ sub: "carol" }, "other-worker");
			for (let i = 0; i < 16; i++) {
				await pause(2);
				expect((await t.lodge({ sub: "carol" }, "other-worker")).status).toBe(201);
			}
			const link = new URL(String(first.body.connect_uri));
			const opened = await (await t.loggedIn()).get(`${link.pathname}${link.search}`);
			expect(opened.status).toBe(400);
		},
	);

	it("refuses a connection the client may not use, and a return URI it did not register", async () => {
		const other = await t.lodge({ connection: "mail" });
		expect([other.status, other.body.error]).toEqual([403, "access_denied"]);
		const unregistered = await t.lodge({ redirect_uri: "https://worker.example/elsewhere" });
		expect([unregistered.status, unregistered.body.error]).toEqual([400, "invalid_request"]);
	});
});

describe("federation grants: refreshing upstream tokens", () => {
	it("refreshes a token near its end, handing the new one", async () => {
		const { id } = await due();
		const before = t.corp.refreshCalls.length;
		const token = await t.grantCall(id, "token");
		expect(token.status).toBe(200);
		expect(token.body.access_token).toMatch(/^upstream-access-\d/);
		expect(t.corp.refreshCalls.length).toBe(before + 1);
	});

	it("ends the credential when the upstream refuses the refresh token: 410 from then on", async () => {
		const { id } = await due();
		t.corp.answerRefresh({ status: 400, json: { error: "invalid_grant" } });
		for (const _ of [1, 2]) {
			const token = await t.grantCall(id, "token");
			expect([token.status, token.body.error]).toEqual([410, "reauthorization_required"]);
		}
		expect((await t.grantCall(id, "status")).body.status).toBe("reauthorization_required");
	});

	it("asks for reauthorization when the upstream wants the user at a refresh: 410 from then on", async () => {
		const { id } = await due();
		t.corp.answerRefresh({ status: 400, json: { error: "interaction_required" } });
		for (const _ of [1, 2]) {
			const token = await t.grantCall(id, "token");
			expect([token.status, token.body.error]).toEqual([410, "reauthorization_required"]);
		}
		const status = (await t.grantCall(id, "status")).body;
		expect([status.status, status.reason]).toEqual([
			"reauthorization_required",
			"upstream_interaction_required",
		]);
	});

	it("keeps the credential while the upstream is down, even with invalid_grant in its body", async () => {
		const { id } = await due();
		t.corp.answerRefresh({ status: 503, json: { error: "invalid_grant" } });
		const during = await t.grantCall(id, "token");
		expect(during.status).toBe(200);
		expect(during.body.access_token).toMatch(/^upstream-access-code-/);
		const after = await t.grantCall(id, "token");
		expect(after.status).toBe(200);
		expect(after.body.access_token).toMatch(/^upstream-access-\d/);
		expect((await t.grantCall(id, "status")).body.status).toBe("active");
	});

	it("keeps the credential while the upstream limits, handing the token that still lives", async () => {
		const { id } = await due();
		t.corp.answerRefresh({
			status: 429,
			headers: { "retry-after": "7" },
			json: { error: "slow_down" },
		});
		const during = await t.grantCall(id, "token");
		expect(during.status).toBe(200);
		expect((await t.grantCall(id, "status")).body.status).toBe("active");
	});

	it("answers 502 for a refreshed token that is not a bearer once the held one has ended", async () => {
		const { id } = await t.connected({ expiresIn: 2 });
		await pause(2100);
		t.corp.answerRefresh({ json: { access_token: "x", token_type: "DPoP", expires_in: 300 } });
		const token = await t.grantCall(id, "token");
		expect([token.status, token.body.error]).toEqual([502, "upstream_token_ineligible"]);
		expect((await t.grantCall(id, "status")).body.status).toBe("upstream_token_ineligible");
	});
});
