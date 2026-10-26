import { describe, expect, it } from "vitest";
import {
	type Answer,
	back,
	connector as harness,
	origin,
	scopes,
	shortToUse,
	upstreamLogin,
	upstreamTokens,
} from "./harness.ts";

/** An answer in a line: its status, the error and its description. */
const said = (answer: Answer) =>
	[answer.status, answer.json?.error, answer.json?.error_description]
		.filter((part) => part !== undefined)
		.join(" ");

describe("a connection in the browser, through the assembled module", () => {
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
		expect((await h.open(flow.link, flow.browser)).opened.status).toBe(400);
		expect((await h.grantCall(flow.id, "status")).json?.status).toBe("pending");
	});

	it("refuses the link to another account's session, and the question and callback to another browser [rfc9700-4.2.4-b]", async () => {
		const h = await harness();
		const lodged = await h.lodge();
		expect((await h.open(lodged.link, await h.login("bob"))).opened.status).toBe(403);
		const alice = await h.login();
		const { challenge } = await h.open(lodged.link, alice);
		const other = await h.login();
		expect((await h.open(lodged.link, other)).opened.status).toBe(400);
		expect((await h.decide(challenge, other)).answered.status).toBe(403);
		const { answered, state } = await h.decide(challenge, alice);
		// Another browser carries no round trip: nothing is spent.
		expect((await h.callback(state, other)).status).toBe(400);
		// The round trip's own cookie in a browser of another session is taken, and refused for it.
		const trip = answered.cookies.find((c) => c.includes("federation-grants.")) ?? "";
		const swapped = await h.browse(
			"GET",
			"/session/federation-grants/callback/cal",
			`${other}; ${trip.split(";")[0] ?? ""}`,
			{ state, code: "c" },
		);
		expect(h.location(swapped).searchParams.get("error")).toBe("reauthentication_required");
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
		const { challenge } = await h.open(lodged.link, alice);
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
		expect((await h.grantCall(lodged.id, "token")).json).toEqual({
			error: "authorization_pending",
		});
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

	it("sends back only to a return the client still lists [rfc9700-4.1.3-b]", async () => {
		const h = await harness();
		const flow = await h.started();
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
		const bob = await h.open(lodged.link, await h.login("bob"));
		expect(bob.opened).toMatchObject({
			status: 403,
			text: "This request was made for another account.",
		});
		short.every = true;
		const alice = await h.login();
		const unknown = await h.open(lodged.link, alice);
		expect(unknown.opened).toMatchObject({ status: 403, text: "Sign in again to continue." });
		short.every = false;
		const raised = await h.open(lodged.link, alice);
		expect(raised.opened.status).toBe(303);
		expect(h.location(raised.opened).pathname).toBe("/raise");
	});

	it("answers a browser with no session with the login page, or 401 without one", async () => {
		const h = await harness({ settings: { "login-page": `${origin}/login` } });
		const anonymous = await h.open((await h.lodge()).link, "");
		expect(h.location(anonymous.opened).searchParams.get("redirect_to")).toBe(anonymous.link.href);
		const plain = await harness();
		expect((await plain.open((await plain.lodge()).link, "")).opened.status).toBe(401);
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
	it("lets a revocation win over an activation that raced it", async () => {
		const h = await harness();
		const flow = await h.started();
		h.stores.raceNext(
			(record) => ({ ...(record as object), status: "revoked", reason: "client" }) as never,
		);
		const done = await h.callback(flow.state, flow.browser);
		expect(h.location(done).searchParams.get("error")).toBe("grant_not_authorizable");
		expect((await h.grantCall(flow.id, "status")).json?.status).toBe("revoked");
	});
});
