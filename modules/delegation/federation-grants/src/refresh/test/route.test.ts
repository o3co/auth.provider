import { describe, expect, it } from "vitest";
import { harness, said, upstreamTokens } from "../../../test/harness.ts";

/** A grant whose token is due: four seconds of life, past half of it. */
async function due(settings: Parameters<typeof harness>[0] = {}) {
	const h = await harness(settings);
	const { id } = await h.connected({ expiresInSeconds: 4 });
	h.advance(2100);
	return { h, id };
}

describe("a grant's token renewed through the token route", () => {
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

	it("lets a revocation win over a refresh that raced it", async () => {
		const { h, id } = await due();
		h.stores.raceNext(
			(record) => ({ ...(record as object), status: "revoked", reason: "client" }) as never,
		);
		expect((await h.grantCall(id, "token")).status).toBe(503);
		expect((await h.grantCall(id, "status")).json?.status).toBe("revoked");
	});
});
