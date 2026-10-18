import { describe, expect, it } from "vitest";
import { harness, said, scopes, upstreamTokens } from "./harness.ts";

/** A grant whose token is due: four seconds of life, past half of it. */
async function due(settings: Parameters<typeof harness>[0] = {}) {
	const h = await harness(settings);
	const { id } = await h.connected({ expiresInSeconds: 4 });
	h.advance(2100);
	return { h, id };
}

describe("refreshing a grant's token", () => {
	it("hands a fresh token without asking the upstream, and refreshes one due with the scopes shown", async () => {
		const { h, id } = await due({ resource: "https://api.example/" });
		const got = await h.grantCall(id, "token");
		expect(got).toMatchObject({ status: 200, json: { access_token: "up-2", expires_in: 300 } });
		expect(h.asked.refreshes).toEqual([["up-refresh-1", scopes, "https://api.example/"]]);
		expect((await h.grantCall(id, "token")).json?.access_token).toBe("up-2");
		expect(h.asked.refreshes.length).toBe(1);
	});

	it("ends the credential only on a structured invalid_grant, answering 410 from then on", async () => {
		const { h, id } = await due();
		h.script.refreshes.push({ kind: "invalid_grant" });
		const refused = {
			status: 410,
			json: { error: "reauthorization_required", error_description: "upstream_invalid_grant" },
		};
		expect(await h.grantCall(id, "token")).toMatchObject(refused);
		expect(await h.grantCall(id, "token")).toMatchObject(refused);
		expect((await h.grantCall(id, "status")).json).toMatchObject({
			status: "reauthorization_required",
		});
		expect(h.asked.refreshes.length).toBe(1);
		expect(h.stores.peek(id)).not.toHaveProperty("sealed");
	});

	it("writes a rotated refresh token before it judges the rest, and marks a token it cannot hold", async () => {
		const { h, id } = await due();
		h.advance(2000);
		h.script.refreshes.push({
			kind: "refreshed",
			tokens: upstreamTokens({ tokenType: "DPoP", refreshToken: "rotated" }),
		});
		expect(said(await h.grantCall(id, "token"))).toBe(
			"502 upstream_token_ineligible upstream_token_ineligible 300",
		);
		expect((await h.grantCall(id, "status")).json).toMatchObject({
			status: "upstream_token_ineligible",
			reason: "upstream_token_ineligible",
		});
		expect((await h.grantCall(id, "token")).status).toBe(200);
		expect(h.asked.refreshes.map(([token]) => token)).toEqual(["up-refresh-1", "rotated"]);
		expect((await h.grantCall(id, "status")).json?.status).toBe("active");
		expect((await h.grantCall(id, "status")).json).not.toHaveProperty("reason");
	});

	it("judges the subject's boundary before it hands a held token or refreshes one", async () => {
		for (const [life, wait] of [
			[300, 1000],
			[4, 2100],
		] as const) {
			const h = await harness();
			const { id } = await h.connected({ expiresInSeconds: life });
			// Left off its subject's listing, so only the read can end it.
			await h.stores.subjects.remove("alice", id);
			h.advance(wait);
			await h.revoke("alice");
			expect(said(await h.grantCall(id, "token"))).toBe("410 grant_revoked backstop");
			expect(h.asked.refreshes).toEqual([]);
		}
	});

	it("lets a revocation win over a refresh that raced it", async () => {
		const { h, id } = await due();
		h.stores.raceNext(
			(record) => ({ ...(record as object), status: "revoked", reason: "client" }) as never,
		);
		expect((await h.grantCall(id, "token")).status).toBe(503);
		expect((await h.grantCall(id, "status")).json?.status).toBe("revoked");
	});
});

describe("a token request's answer to what the refresh came to", () => {
	const narrow = { kind: "refreshed", tokens: upstreamTokens({ scope: ["openid"] }) } as const;
	for (const [upstream, asked, answer] of [
		["unreachable", {}, "503 temporarily_unavailable"],
		[{ kind: "limited", retryAfterSeconds: 7 }, {}, "429 rate_limited provider 7"],
		[narrow, { scope: "read" }, "400 invalid_scope"],
	] as const) {
		it(answer, async () => {
			const h = await harness();
			const { id } = await h.connected({ expiresInSeconds: 4 });
			h.script.refreshes.push(upstream);
			h.advance(4100);
			expect(said(await h.grantCall(id, "token", asked))).toBe(answer);
		});
	}
});
