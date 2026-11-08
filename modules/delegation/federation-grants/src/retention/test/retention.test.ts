import { expect, it } from "vitest";
import { harness } from "../../../test/harness.ts";

it("keeps a grant's record retention past the point it can no longer be used, one never connected included", async () => {
	const h = await harness({ settings: { retention: "1d" } });
	const id = String((await h.lodge()).json?.grant_id);
	h.advance(600_000 + 86_400_000 - 1);
	expect(h.stores.peek(id)).toMatchObject({ status: "pending" });
	h.advance(1);
	expect(h.stores.peek(id)).toBeUndefined();
});

it("keeps a revoked grant's record retention past its revocation, and its subject no longer lists it", async () => {
	const h = await harness({ settings: { retention: "1d" } });
	const { id } = await h.connected();
	h.advance(86_400_000);
	expect((await h.grantCall(id, "revoke")).status).toBe(204);
	const listed = await h.stores.subjects.members("alice");
	expect(listed.map((m) => m.member)).not.toContain(id);
	h.advance(86_400_000 - 1);
	expect((await h.grantCall(id, "token")).status).toBe(410);
	h.advance(1);
	expect((await h.grantCall(id, "token")).status).toBe(404);
});

it("keeps a grant revoked past its end no longer than retention past that end", async () => {
	const h = await harness({ settings: { retention: "1d", "default-lifetime": "1h" } });
	const { id } = await h.connected();
	h.advance(7_200_000);
	await h.grantCall(id, "revoke");
	h.advance(86_400_000 - 3_600_000 - 1);
	expect(h.stores.peek(id)).toMatchObject({ status: "revoked" });
	h.advance(1);
	expect(h.stores.peek(id)).toBeUndefined();
});
