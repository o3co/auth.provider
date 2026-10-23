import { describe, expect, it } from "vitest";
import { back, harness } from "../../../test/harness.ts";

type Harness = Awaited<ReturnType<typeof harness>>;

const revocations = (h: Harness) =>
	h.events.filter((e) => e.kind === "federation.grant.revoked").map((e) => e.attributes?.outcome);
const listed = async (h: Harness) =>
	(await h.stores.subjects.members("alice")).map(({ member }) => member);

describe("following a subject's revocation", () => {
	it("leaves another subject's grant listed under it, and an intent started after the revocation", async () => {
		const h = await harness();
		const bobs = String((await h.lodge({ sub: "bob" })).json?.grant_id);
		await h.stores.subjects.add("alice", bobs, 60_000);
		await h.stores.subjects.add("alice", "gone", 60_000);
		h.advance(10_000);
		const late = String((await h.lodge()).json?.grant_id);
		// A host whose clock is behind records the revocation after the lodging.
		h.advance(-5000);
		await h.revoke("alice");
		expect(h.stores.peek(bobs)).toMatchObject({ status: "pending" });
		expect(h.stores.peek(late)).toMatchObject({ status: "pending" });
		expect(await listed(h)).toEqual([late]);
	});

	it("ends a pending intent begun in the revocation's second, and leaves one begun in the next, allowing nothing for clocks", async () => {
		const h = await harness();
		const same = String((await h.lodge()).json?.grant_id);
		h.advance(1000);
		const next = String((await h.lodge()).json?.grant_id);
		h.advance(-1000);
		await h.revoke("alice");
		expect(h.stores.peek(same)).not.toMatchObject({ status: "pending" });
		expect(h.stores.peek(next)).toMatchObject({ status: "pending" });
		expect(await listed(h)).toEqual([next]);
	});

	it("writes nothing over a revocation or a renewal another writer made meanwhile", async () => {
		const h = await harness();
		const { id } = await h.connected();
		h.meanwhile({ status: "revoked", reason: "client" });
		h.advance(1000);
		await h.revoke("alice");
		expect(h.stores.peek(id)).toMatchObject({ reason: "client" });
		expect(revocations(h)).toEqual([]);
		expect(await listed(h)).toEqual([]);
		for (const intent of [{ id: "another" }, { ended: "connected" }]) {
			const kept = await harness({ settings: { "keep-on-subject-revocation": true } });
			const { id: renewed } = await kept.connected();
			await kept.grantCall(renewed, "reauthorize", { redirect_uri: back, state: "r" });
			kept.meanwhile({}, intent);
			kept.advance(1000);
			await kept.revoke("alice", true);
			const left = (kept.stores.peek(renewed) as unknown as { intent: object }).intent;
			expect(left, JSON.stringify(intent)).toMatchObject(intent);
			expect(left).not.toHaveProperty("ended", "subject_revoked");
			expect(await listed(kept)).toEqual([renewed]);
		}
	});
});
