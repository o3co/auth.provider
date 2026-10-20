import { expect, it } from "vitest";
import { harness } from "../../../test/harness.ts";

it("audits a token route the store cannot answer as the route's refusal, unavailable, whatever the record does", async () => {
	const h = await harness();
	const { id } = await h.connected();
	h.stores.down.failNext("read");
	expect((await h.grantCall(id, "token")).status).toBe(503);
	const denied = h.events.filter((e) => e.kind === "federation.grant.token.denied");
	expect(denied.map((e) => [e.attributes?.client, e.attributes?.reason])).toEqual([
		["worker", "unavailable"],
	]);
	// Recording is best effort: a record that throws leaves the answer a 503.
	const push = h.events.push;
	h.events.push = () => {
		throw new Error("record failed");
	};
	h.stores.down.failNext("read");
	expect((await h.grantCall(id, "token")).status).toBe(503);
	h.events.push = push;
	// Anything else that throws is not an outage, and is not audited as one.
	const due = await h.connected({ expiresInSeconds: 4 });
	h.advance(5000);
	h.stores.lockStore.hold = async () => {
		throw new Error("broken");
	};
	await expect(h.grantCall(due.id, "token")).rejects.toThrow("broken");
	expect(h.events.filter((e) => e.attributes?.reason === "unavailable")).toHaveLength(1);
});
