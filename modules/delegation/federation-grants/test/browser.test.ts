import { describe, expect, it } from "vitest";
import { back, harness, scopes, upstreamLogin, upstreamTokens } from "./harness.ts";

type Harness = Awaited<ReturnType<typeof harness>>;

const errorOf = (h: Harness, answer: { headers: Record<string, string> }) =>
	h.location(answer as never).searchParams.get("error");

describe("the callback of a renewal", () => {
	it("refuses a renewal whose grant a revocation since covers", async () => {
		const r = await harness();
		const made = await r.connected();
		await r.stores.subjects.remove("alice", made.id);
		r.advance(10_000);
		const renewed = await r.grantCall(made.id, "reauthorize", { redirect_uri: back, state: "r" });
		// A host whose clock is behind records the revocation after the renewal started.
		r.advance(-5000);
		await r.revoke("alice");
		r.advance(5000);
		const browser = await r.login();
		const answered = await r.decide((await r.open(renewed, browser)).challenge, browser);
		expect(errorOf(r, await r.callback(answered.state, browser))).toBe("access_denied");
	});

	it("renews a grant clearing its reason and rotations, audited as a renewal", async () => {
		const h = await harness({ settings: { rotations: 1, "rotation-window": "1h" } });
		const { id } = await h.connected({ expiresInSeconds: 4 });
		h.advance(2100);
		h.script.refreshes.push({
			kind: "refreshed",
			tokens: upstreamTokens({ scope: [...scopes, "write"], expiresInSeconds: 4 }),
		});
		await h.grantCall(id, "token");
		expect((await h.grantCall(id, "status")).json?.reason).toBe("scope_exceeded");
		const renewal = await h.grantCall(id, "reauthorize", { redirect_uri: back, state: "r" });
		const alice = await h.login();
		const { state } = await h.decide((await h.open(renewal, alice)).challenge, alice);
		h.script.exchange = async () => ({
			...upstreamLogin(),
			tokens: upstreamTokens({ expiresInSeconds: 4 }),
		});
		await h.callback(state, alice);
		expect((await h.grantCall(id, "status")).json).not.toHaveProperty("reason");
		expect(h.events.map((e) => e.kind)).toContain("federation.grant.reauthorized");
		h.advance(2100);
		expect((await h.grantCall(id, "token")).status).toBe(200);
		expect(h.asked.refreshes.length).toBe(2);
	});

	it("says in a renewal's audit that the account moved, by no value, and of one that did not, nothing", async () => {
		const h = await harness();
		const { id } = await h.connected({ expiresInSeconds: 3600 });
		const renewed = async () => {
			const renewal = await h.grantCall(id, "reauthorize", { redirect_uri: back, state: "r" });
			const alice = await h.login();
			const { state } = await h.decide((await h.open(renewal, alice)).challenge, alice);
			await h.callback(state, alice);
			return h.events.filter((e) => e.kind === "federation.grant.reauthorized").at(-1)?.attributes;
		};
		expect(await renewed()).not.toHaveProperty("account_changed");
		const elsewhere = "https://elsewhere.example";
		h.script.issuer = elsewhere;
		h.script.exchange = async () => ({ ...upstreamLogin(), issuer: elsewhere });
		expect(await renewed()).toMatchObject({ account_changed: "issuer" });
		h.script.exchange = async () => ({ ...upstreamLogin(), issuer: elsewhere, subject: "u-other" });
		expect(await renewed()).toMatchObject({ account_changed: "subject" });
	});

	it("lists an activated grant for its life, so a revocation long after its connection ends it", async () => {
		const h = await harness();
		const { id } = await h.connected();
		h.advance(601_000);
		await h.revoke("alice");
		expect(h.stores.peek(id)).toMatchObject({ status: "revoked" });
	});
});
