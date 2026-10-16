import { csrfChecked } from "@mod/csrf";
import { describe, expect, it } from "vitest";
import {
	back,
	harness,
	origin,
	said,
	scopes,
	shortToUse,
	upstreamLogin,
	upstreamTokens,
} from "./harness.ts";

describe("connecting a grant", () => {
	it("lodges an intent, asks the user, sends the browser upstream and activates on the callback", async () => {
		const h = await harness();
		const flow = await h.started();
		expect(flow.lodged.status).toBe(201);
		expect(flow.lodged.json).toMatchObject({
			status: "pending",
			connect_expires_in: 600,
			expires_in: 2_592_000,
		});
		expect(String(flow.lodged.json?.connect_uri)).toMatch(
			`${origin}/session/federation-grants/connect?request=`,
		);
		expect(h.location(flow.opened).href).toMatch(`${origin}/consent-page?challenge=`);
		// An answered question is no longer shown.
		const shown = await h.browse("GET", "/session/federation-grants/consent", flow.browser, {
			challenge: flow.challenge,
		});
		expect(shown.status).toBe(400);
		const start = h.asked.starts[0];
		expect(start).toMatchObject({
			scopes,
			challengeMethod: "S256",
			redirectUri: `${origin}/session/federation-grants/callback/cal`,
		});
		const done = await h.callback(flow.state, flow.browser);
		expect(done.status).toBe(303);
		expect(done.headers.location).toBe(`${back}?grant_id=${flow.id}&state=st`);
		const token = await h.grantCall(flow.id, "token");
		expect(token).toMatchObject({
			status: 200,
			json: { access_token: "up-1", token_type: "Bearer", scope: scopes.join(" ") },
		});
		expect((await h.grantCall(flow.id, "status")).json).toMatchObject({
			status: "active",
			upstream: { subject: "u-alice" },
		});
		expect(h.events.map((e) => e.kind)).toContain("federation.grant.authorized");
	});

	it("holds the answer to the CSRF policy", async () => {
		const h = await harness();
		const answer = h.routes.find(
			(r) => r.method === "POST" && r.path === "/session/federation-grants/consent",
		);
		expect(answer?.uses?.map((u) => u.policy)).toContain(csrfChecked);
	});

	it("answers an upstream whose authorization URL throws at once as unavailable, leaving the question open", async () => {
		const h = await harness();
		h.script.startThrows = true;
		const flow = await h.started();
		expect(said(flow.answered)).toBe("503 temporarily_unavailable upstream_unavailable");
		expect(h.events.map((e) => e.attributes?.outcome)).toContain("upstream_unavailable");
		h.script.startThrows = false;
		h.script.withdrawn = true;
		expect((await h.decide(flow.challenge, flow.browser)).answered.status).toBe(503);
		h.script.withdrawn = false;
		const again = await h.browse("POST", "/session/federation-grants/consent", flow.browser, {
			challenge: flow.challenge,
			decision: "accept",
		});
		expect(again.status).toBe(303);
		expect(h.location(again).origin).toBe("https://up.example");
	});

	it("ends the intent a start the upstream refuses, and sends the browser back to the client", async () => {
		const h = await harness();
		h.script.startRefused = true;
		const flow = await h.started();
		expect(flow.answered.status).toBe(303);
		expect(flow.answered.headers.location).toBe(
			`${back}?grant_id=${flow.id}&state=st&error=grant_not_authorizable`,
		);
		const failed = h.events.filter((e) => e.kind === "federation.grant.authorization_failed");
		expect(failed.map((e) => e.attributes?.outcome)).toEqual(["upstream_refused_start"]);
		h.script.startRefused = false;
		expect((await h.open(flow.lodged, flow.browser)).opened.status).toBe(400);
		expect((await h.grantCall(flow.id, "status")).json?.status).toBe("pending");
	});

	it("refuses the link to another account's session, and the question and callback to another browser", async () => {
		const h = await harness();
		const lodged = await h.lodge();
		expect((await h.open(lodged, await h.login("bob"))).opened.status).toBe(403);
		const alice = await h.login();
		const { challenge } = await h.open(lodged, alice);
		const other = await h.login();
		expect((await h.open(lodged, other)).opened.status).toBe(400);
		expect((await h.decide(challenge, other)).answered.status).toBe(403);
		const { state } = await h.decide(challenge, alice);
		const elsewhere = await h.callback(state, other);
		expect(h.location(elsewhere).searchParams.get("error")).toBe("reauthentication_required");
		// The state was spent: the right browser cannot use it after.
		expect((await h.callback(state, alice)).status).toBe(400);
	});

	it("spends the state only at the connection it was made for", async () => {
		const h = await harness();
		const flow = await h.started();
		const wrong = await h.browse("GET", "/session/federation-grants/callback/mail", flow.browser, {
			state: flow.state,
			code: "c",
		});
		expect(wrong.status).toBe(400);
		expect((await h.callback(flow.state, flow.browser)).status).toBe(303);
	});

	it("shows the question, and sends a refused one back with access_denied, and ends the intent", async () => {
		const h = await harness();
		const lodged = await h.lodge();
		const alice = await h.login();
		const { challenge } = await h.open(lodged, alice);
		const shown = await h.browse("GET", "/session/federation-grants/consent", alice, { challenge });
		expect(shown.json).toMatchObject({
			client_id: "worker",
			connection: "cal",
			scopes,
			continues_after_logout: true,
			expires_in: 600,
		});
		const denied = await h.decide(challenge, alice, "deny");
		expect(h.location(denied.answered).searchParams.get("error")).toBe("access_denied");
		expect((await h.grantCall(String(lodged.json?.grant_id), "token")).json).toEqual({
			error: "authorization_pending",
		});
	});

	it("reads each part of the upstream's tokens once, refusing a part that throws", async () => {
		const h = await harness();
		let reads = 0;
		const tokens = upstreamTokens();
		const once = Object.defineProperty({ ...tokens }, "accessToken", {
			get: () => {
				reads++;
				if (reads > 1) throw new Error("read twice");
				return "up-once";
			},
		});
		h.script.exchange = async () => upstreamLogin(once);
		const flow = await h.started();
		await h.callback(flow.state, flow.browser);
		expect((await h.grantCall(flow.id, "token")).json?.access_token).toBe("up-once");
		expect(reads).toBe(1);
	});

	it("refuses another upstream account than the grant holds", async () => {
		const h = await harness();
		const { id } = await h.connected();
		const renewal = await h.grantCall(id, "reauthorize", { redirect_uri: back, state: "r" });
		const alice = await h.login();
		const { state } = await h.decide((await h.open(renewal, alice)).challenge, alice);
		h.script.exchange = async () => upstreamLogin(upstreamTokens(), "u-else");
		expect(h.location(await h.callback(state, alice)).searchParams.get("error")).toBe(
			"account_mismatch",
		);
		expect((await h.grantCall(id, "token")).status).toBe(200);
	});

	it("sends back only to a return the client still lists", async () => {
		const h = await harness();
		const flow = await h.started({ redirect_uri: back });
		h.relist(["cal"], []);
		const done = await h.callback(flow.state, flow.browser);
		expect(done.status).toBe(400);
		expect(done.headers.location).toBeUndefined();
	});

	it("checks whose session it is before it spends the intent's one step-up", async () => {
		const short = { every: false };
		const h = await harness({
			settings: { "step-up-page": `${origin}/raise` },
			requirements: [shortToUse(short)],
		});
		const lodged = await h.lodge();
		const bob = await h.open(lodged, await h.login("bob"));
		expect(bob.opened).toMatchObject({
			status: 403,
			text: "This request was made for another account.",
		});
		short.every = true;
		const alice = await h.login();
		const unknown = await h.open(lodged, alice);
		expect(unknown.opened).toMatchObject({ status: 403, text: "Sign in again to continue." });
		short.every = false;
		const raised = await h.open(lodged, alice);
		expect(raised.opened.status).toBe(303);
		expect(h.location(raised.opened).pathname).toBe("/raise");
	});

	it("answers a browser with no session with the login page, or 401 without one", async () => {
		const h = await harness({ settings: { "login-page": `${origin}/login` } });
		const anonymous = await h.open(await h.lodge(), "");
		expect(h.location(anonymous.opened).searchParams.get("redirect_to")).toBe(anonymous.link.href);
		const plain = await harness();
		expect((await plain.open(await plain.lodge(), "")).opened.status).toBe(401);
	});

	it("ends a pending grant a subject's revocation reached before its callback", async () => {
		const h = await harness();
		const flow = await h.started();
		h.advance(1000);
		await h.revoke("alice");
		const done = await h.callback(flow.state, flow.browser);
		expect(done.status).toBe(400);
		expect((await h.grantCall(flow.id, "status")).json?.status).toBe("revoked");
	});

	it("audits every failed connection, with no upstream text", async () => {
		const h = await harness();
		const { done } = await h.connected({ tokenType: "mac" });
		expect(done.status).toBe(303);
		const failed = h.events.filter((e) => e.kind === "federation.grant.authorization_failed");
		expect(failed.map((e) => e.attributes?.outcome)).toEqual(["upstream_token_ineligible"]);
		expect(JSON.stringify(h.events)).not.toContain("up-refresh-1");
	});
});
