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

	it("ends no grant of a type whose delegation says no issuer, as the upstream says it", async () => {
		const { h, id } = await due();
		const answered = await h.grantCall(id, "token");
		expect(answered.status).toBe(200);
		expect(h.asked.refreshes).toHaveLength(1);
		expect((await h.grantCall(id, "status")).json).toMatchObject({ status: "active" });
	});

	it("asks nothing of another issuer behind the connection, answering reauthorization_required and erasing the credential", async () => {
		const { h, id } = await due();
		h.script.issuer = "https://another.example";
		expect(said(await h.grantCall(id, "token"))).toBe(
			"410 reauthorization_required upstream_issuer_changed",
		);
		expect(h.asked.refreshes).toEqual([]);
		expect((await h.grantCall(id, "status")).json).toMatchObject({
			status: "reauthorization_required",
			reason: "upstream_issuer_changed",
		});
		expect(said(await h.grantCall(id, "token"))).toBe(
			"410 reauthorization_required upstream_issuer_changed",
		);
		expect(h.asked.refreshes).toEqual([]);
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
