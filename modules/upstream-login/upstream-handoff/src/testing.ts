/** For tests: what any implementation of the held login store interface must do. */
import { describe, expect, it } from "vitest";
import type { HeldLoginStore, StoredHeldLogin } from "./store.ts";

/** A place that keeps held logins, as one implementation of the store interface offers it. */
export interface HeldLoginPlace {
	readonly held: HeldLoginStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `name` writes, another writer changes its record as given. */
	raceNextUpdate(name: string, change: (record: StoredHeldLogin) => StoredHeldLogin): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/**
 * What the package needs from any implementation of its store interface: records kept whole and
 * once, changed only from what they hold, ended at exactly their lifetime, and a change once
 * answered kept through a failover.
 */
export function heldLoginStoreContract(name: string, open: () => Promise<HeldLoginPlace>): void {
	let n = 0;
	const fresh = () => `t-${++n}-${Math.random().toString(36).slice(2)}`;
	/** A value as the store keeps it, whatever its shape. */
	const asStored = (value: object) => value as unknown as StoredHeldLogin;
	const counted = (record: StoredHeldLogin) => (record as unknown as { n: number }).n;
	const plus = (record: StoredHeldLogin) => ({ value: asStored({ n: counted(record) + 1 }) });
	const read = async (held: HeldLoginStore, key: string) =>
		(await held.update(key, () => undefined))?.after;

	describe(`upstream-handoff's store interface: ${name}`, () => {
		it("removes a record, so its name is free again", async () => {
			const place = await open();
			const [key, other] = [fresh(), fresh()];
			await place.held.save(key, asStored({ n: 1 }), 60_000);
			await place.held.save(other, asStored({ n: 2 }), 60_000);
			await place.held.remove(key);
			await place.held.remove(fresh());
			expect(await read(place.held, key)).toBeUndefined();
			expect(await read(place.held, other)).toEqual(asStored({ n: 2 }));
			expect(await place.held.save(key, asStored({ n: 3 }), 60_000)).toBe("created");
		});

		it("keeps a record whole and once per name, and changes it only from what it holds", async () => {
			const place = await open();
			const key = fresh();
			const odd = asStored({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await place.held.save(key, odd, 60_000)).toBe("created");
			expect(await place.held.save(key, asStored({ n: 1 }), 60_000)).toBe("exists");
			expect(await read(place.held, key)).toEqual(odd);
			expect(await place.held.update(fresh(), plus)).toBeUndefined();
			const counting = fresh();
			await place.held.save(counting, asStored({ n: 1 }), 60_000);
			place.raceNextUpdate(counting, (record) => asStored({ n: counted(record) * 10 }));
			expect(await place.held.update(counting, plus)).toEqual({
				before: asStored({ n: 10 }),
				after: asStored({ n: 11 }),
			});
		});

		it("ends a record at exactly its lifetime", async () => {
			const place = await open();
			const key = fresh();
			await place.held.save(key, asStored({ n: 1 }), 1000);
			place.advance(999);
			expect(await read(place.held, key)).toBeDefined();
			place.advance(1);
			expect(await read(place.held, key)).toBeUndefined();
		});

		it("never gives a held login's carry to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [carry, kept] = [fresh(), fresh()];
			await place.held.save(carry, asStored({ kept }), 60_000);
			await place.held.update(carry, (record) => ({ value: record }));
			expect([holds(kept), holds(carry)]).toEqual([true, false]);
		});

		it("keeps a change whose answer was lost, through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			await place.held.save(key, asStored({ n: 1 }), 60_000);
			lose();
			expect((await place.held.update(key, plus))?.after).toEqual(asStored({ n: 2 }));
			await failover();
			expect(await read(place.held, key)).toEqual(asStored({ n: 2 }));
		});
	});
}
