import { Unavailable } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { describe, expect, it } from "vitest";
import { denylistAllowanceMs, denylistOver, type RevokedTokens } from "../src/contract.ts";

/** A store in memory on the clock the denylist reads, that can stop answering. */
function kept(now: () => number) {
	const place = { down: false, saved: [] as [string, number][] };
	const stand = memoryRecords<true>(now, { shards: 1, perShard: 1 });
	const store: RevokedTokens = {
		save: async (id, lifetimeMs) => {
			if (place.down) throw new Unavailable("revoked tokens");
			place.saved.push([id, lifetimeMs]);
			return stand.records.create(id, true, lifetimeMs);
		},
		holds: async (id) => {
			if (place.down) throw new Unavailable("revoked tokens");
			return (await stand.records.read(id)) !== undefined;
		},
	};
	return { store, place };
}

describe("the denylist", () => {
	let now = 1_000_000;
	const clock = { now: () => now };

	it("keeps a revoked id for what is left of the token and the allowance, and holds it that long", async () => {
		const { store, place } = kept(clock.now);
		const denylist = denylistOver(store, clock);
		expect(denylist.revocable).toBe(true);
		expect(await denylist.revoke("a", now + 5_000)).toEqual({ kind: "revoked" });
		expect(place.saved).toEqual([["a", 5_000 + 60_000]]);
		expect(denylistAllowanceMs).toBe(60_000);
		expect(await denylist.holds("a")).toBe(true);
		expect(await denylist.revoke("a", now + 5_000)).toEqual({ kind: "revoked" });
		now += 65_000;
		expect(await denylist.holds("a")).toBe(false);
	});

	it("revokes a token past its expiry while within the allowance, and none past that", async () => {
		const { store } = kept(clock.now);
		const denylist = denylistOver(store, clock);
		expect(await denylist.revoke("late", now - 59_999)).toEqual({ kind: "revoked" });
		expect(await denylist.revoke("gone", now - 60_000)).toEqual({ kind: "invalid" });
	});

	it("revokes nothing and holds nothing without a store", async () => {
		const denylist = denylistOver(undefined, clock);
		expect(denylist.revocable).toBe(false);
		expect(await denylist.revoke("a", now + 5_000)).toEqual({ kind: "unsupported" });
		expect(await denylist.holds("a")).toBe(false);
	});

	it("answers unavailable while the store does, never a negative verdict", async () => {
		const { store, place } = kept(clock.now);
		const denylist = denylistOver(store, clock);
		place.down = true;
		await expect(denylist.revoke("a", now + 5_000)).rejects.toBeInstanceOf(Unavailable);
		await expect(denylist.holds("a")).rejects.toBeInstanceOf(Unavailable);
	});
});
