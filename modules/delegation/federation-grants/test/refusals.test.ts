import { testRequest } from "@mod/http/testing";
import { describe, expect, it } from "vitest";
import { routeCases } from "./fixtures/routes.ts";
import { back, harness, said, upstreamTokens } from "./harness.ts";

type Harness = Awaited<ReturnType<typeof harness>>;

/** Sets up the grant a case names, and answers its id. */
const grantIn = async (h: Harness, grant: string | undefined) => {
	if (grant === "unknown") return "unknown";
	if (grant === "pending") return String((await h.lodge()).json?.grant_id);
	const { id } = await h.connected();
	if (grant === "revoked") await h.grantCall(id, "revoke");
	if (grant === "expired") h.advance(2_592_000_000);
	return id;
};
const denials = (h: Harness, from: number) =>
	h.events
		.slice(from)
		.filter((e) => e.kind.endsWith(".denied"))
		.map((e) => e.attributes?.reason ?? e.attributes?.outcome);

describe("the client routes' answers", () => {
	for (const c of routeCases) {
		it(c.name, async () => {
			const h = await harness({ settings: c.settings ?? {} });
			const id = c.id ?? (c.step ? await grantIn(h, c.grant) : "");
			if (c.disallowed) h.relist([], [back]);
			h.script.withdrawn = c.withdrawn === true;
			const from = h.events.length;
			const answer = c.step
				? await h.grantCall(id, c.step, c.body, c.as)
				: await h.lodge(c.body, c.as);
			expect(said(answer)).toBe(c.said);
			if (c.audited !== undefined) expect(denials(h, from)).toEqual(c.audited ? [c.audited] : []);
		});
	}

	it("answers a wrong secret with the challenges", async () => {
		const h = await harness();
		const basic = `Basic ${Buffer.from("worker:nope").toString("base64")}`;
		const path = "/oauth/federation-grants";
		const json = { connection: "cal", sub: "alice", redirect_uri: back, state: "s" };
		const headers = new Map([["authorization", basic]]);
		const wrong = await h.send(testRequest({ method: "POST", path, json, headers }));
		expect(wrong.status).toBe(401);
		expect(wrong.headers["www-authenticate"]).toBeTruthy();
		const spa = await h.send(
			testRequest({ method: "POST", path, json: { ...json, client_id: "spa" } }),
		);
		expect(said(spa)).toBe("401 invalid_client");
	});
});

describe("lodging", () => {
	it("leaves the reason an intent ended with when a later lodging pushes it out", async () => {
		const h = await harness();
		const lodged = await h.lodge();
		const alice = await h.login();
		await h.decide((await h.open(lodged, alice)).challenge, alice, "deny");
		for (const _ of [1, 2, 3]) {
			h.advance(1);
			await h.lodge();
		}
		const id = String(lodged.json?.grant_id);
		expect(h.stores.peek(id)).toMatchObject({ intent: { ended: "access_denied" } });
	});

	it("audits the subject cut short, with the request's source", async () => {
		const h = await harness();
		await h.lodge({ sub: "a".repeat(300) });
		const requested = h.events.find((e) => e.kind === "federation.grant.requested");
		expect(requested?.subject).toBe("a".repeat(200));
		expect(requested?.attributes?.source).toBe("127.0.0.1");
	});
});

describe("renewing", () => {
	it("answers 503 to a renewal a revocation overtook, and writes nothing over it", async () => {
		const h = await harness();
		const { id } = await h.connected();
		h.stores.raceNext(
			(record) => ({ ...(record as object), status: "revoked", reason: "client" }) as never,
		);
		const renewal = await h.grantCall(id, "reauthorize", { redirect_uri: back, state: "r" });
		expect(renewal.status).toBe(503);
		expect(h.stores.peek(id)).toMatchObject({ status: "revoked", intent: { ended: "connected" } });
	});

	it("renews a grant whose upstream answered wider than shown, and no other ineligible one", async () => {
		for (const [more, status] of [
			[{ scope: ["openid", "offline_access", "read", "write"] }, 201],
			[{ tokenType: "DPoP" }, 502],
		] as const) {
			const h = await harness();
			const { id } = await h.connected({ expiresInSeconds: 4 });
			h.advance(4100);
			h.script.refreshes.push({ kind: "refreshed", tokens: upstreamTokens(more) });
			await h.grantCall(id, "token");
			const renewal = await h.grantCall(id, "reauthorize", { redirect_uri: back, state: "r" });
			expect(renewal.status, JSON.stringify(more)).toBe(status);
		}
	});
});

describe("a token request", () => {
	it("refuses a wider scope on a token that is due without asking the upstream", async () => {
		const h = await harness();
		const { id } = await h.connected({ expiresInSeconds: 4 });
		h.advance(2100);
		expect((await h.grantCall(id, "token", { scope: "openid write" })).status).toBe(400);
		expect(h.asked.refreshes).toEqual([]);
	});

	it("says a token lives no longer than its grant", async () => {
		const h = await harness();
		const flow = await h.started({ expires_in: 120 });
		await h.callback(flow.state, flow.browser);
		expect((await h.grantCall(flow.id, "token")).json?.expires_in).toBe(120);
	});

	it("says unknown when the upstream refuses a refresh without a reason", async () => {
		const h = await harness();
		const { id } = await h.connected({ expiresInSeconds: 4 });
		h.advance(4100);
		h.script.refreshes.push("refused");
		expect(said(await h.grantCall(id, "token"))).toBe("502 upstream_rejected unknown 300");
	});

	it("notes no use on a grant revoked as its token was handed, and fails on a store fault that is no outage", async () => {
		const h = await harness();
		const { id } = await h.connected();
		h.stores.raceNext(
			(record) => ({ ...(record as object), status: "revoked", reason: "client" }) as never,
		);
		expect((await h.grantCall(id, "token")).status).toBe(200);
		expect(h.stores.peek(id)).not.toHaveProperty("lastUsedAt");
		const { id: other } = await h.connected();
		h.stores.raceNext(() => {
			throw new TypeError("not now");
		});
		await expect(h.grantCall(other, "token")).rejects.toThrow(TypeError);
	});
});

describe("status and revocation", () => {
	it("answers a revoked grant past its life as revoked, an ended one without its reason, and a pending one without a scope", async () => {
		const h = await harness();
		const pending = String((await h.lodge()).json?.grant_id);
		expect((await h.grantCall(pending, "status")).json).not.toHaveProperty("scope");
		const { id: revoked } = await h.connected();
		await h.grantCall(revoked, "revoke");
		const { id: marked } = await h.connected({ expiresInSeconds: 4 });
		h.advance(4100);
		h.script.refreshes.push({ kind: "refreshed", tokens: upstreamTokens({ tokenType: "DPoP" }) });
		await h.grantCall(marked, "token");
		expect((await h.grantCall(marked, "status")).json?.reason).toBe("upstream_token_ineligible");
		h.advance(2_592_000_000);
		expect((await h.grantCall(revoked, "status")).json).toMatchObject({
			status: "revoked",
			reason: "client",
		});
		expect((await h.grantCall(marked, "status")).json).not.toHaveProperty("reason");
	});

	it("erases the credentials at a client's revocation, and leaves the first revocation's reason", async () => {
		const h = await harness();
		const { id } = await h.connected();
		await h.grantCall(id, "revoke");
		expect(h.stores.peek(id)).not.toHaveProperty("sealed");
		const { id: ended } = await h.connected();
		h.advance(1000);
		await h.revoke("alice");
		await h.grantCall(ended, "revoke");
		expect((await h.grantCall(ended, "status")).json?.reason).toBe("backstop");
	});
});

describe("the read's judgment of a subject's revocation", () => {
	it("ends a grant the follower missed, erasing its credentials and auditing it once; a client's revocation of it stays the client's", async () => {
		const h = await harness();
		const [{ id }, { id: asked }] = [await h.connected(), await h.connected()];
		for (const missed of [id, asked]) await h.stores.subjects.remove("alice", missed);
		h.advance(1000);
		await h.revoke("alice");
		expect((await h.grantCall(id, "status")).json?.status).toBe("revoked");
		await h.grantCall(id, "token");
		expect(h.stores.peek(id)).not.toHaveProperty("sealed");
		const revoked = h.events.filter((e) => e.kind === "federation.grant.revoked");
		expect(revoked.map((e) => e.attributes?.outcome)).toEqual(["backstop"]);
		expect((await h.grantCall(asked, "revoke")).status).toBe(204);
		expect((await h.grantCall(asked, "status")).json?.reason).toBe("client");
	});

	it("answers a grant gone before the read's write as revoked, auditing nothing", async () => {
		const h = await harness();
		const { id } = await h.connected();
		await h.stores.subjects.remove("alice", id);
		h.advance(1000);
		await h.revoke("alice");
		h.stores.raceNext(() => ({}) as never);
		expect(said(await h.grantCall(id, "token"))).toBe("410 grant_revoked backstop");
		expect(h.events.filter((e) => e.kind === "federation.grant.revoked")).toEqual([]);
	});

	it("erases credentials past the end only while the grant is still past it", async () => {
		const h = await harness();
		const { id } = await h.connected();
		h.advance(2_592_000_000);
		const later = h.now() + 60_000;
		// A renewal activating meanwhile, as it writes: a new authorization and a new end.
		h.stores.raceNext(
			(record) => ({ ...(record as object), authorizedAt: h.now(), expiresAt: later }) as never,
		);
		await h.grantCall(id, "status");
		expect(h.stores.peek(id)).toHaveProperty("sealed");
	});
});
