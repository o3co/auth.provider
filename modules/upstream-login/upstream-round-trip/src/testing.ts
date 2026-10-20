/** For tests: what any implementation of the round trip store interface must do. */
import { describe, expect, it } from "vitest";
import type { RoundTripStore, StoredRoundTrip } from "./store.ts";

/** A place that keeps round trips, as one implementation of the store interface offers it. */
export interface RoundTripPlace {
	readonly roundTrips: RoundTripStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `name` writes, another writer changes its record as given. */
	raceNextUpdate(name: string, change: (record: StoredRoundTrip) => StoredRoundTrip): void;
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
export function roundTripStoreContract(name: string, open: () => Promise<RoundTripPlace>): void {
	let n = 0;
	const fresh = () => `r-${++n}-${Math.random().toString(36).slice(2)}`;
	/** A value as the store keeps it, whatever its shape. */
	const asStored = (value: object) => value as unknown as StoredRoundTrip;
	const counted = (record: StoredRoundTrip) => (record as unknown as { n: number }).n;
	const plus = (record: StoredRoundTrip) => ({ value: asStored({ n: counted(record) + 1 }) });
	const read = async (trips: RoundTripStore, key: string) =>
		(await trips.update(key, () => undefined))?.after;

	describe(`upstream-round-trip's store interface: ${name}`, () => {
		it("keeps a record whole and once per name, and changes it only from what it holds", async () => {
			const place = await open();
			const key = fresh();
			const odd = asStored({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await place.roundTrips.save(key, odd, 60_000)).toBe("created");
			expect(await place.roundTrips.save(key, asStored({ n: 1 }), 60_000)).toBe("exists");
			expect(await read(place.roundTrips, key)).toEqual(odd);
			expect(await place.roundTrips.update(fresh(), plus)).toBeUndefined();
			const counting = fresh();
			await place.roundTrips.save(counting, asStored({ n: 1 }), 60_000);
			place.raceNextUpdate(counting, (record) => asStored({ n: counted(record) * 10 }));
			expect(await place.roundTrips.update(counting, plus)).toEqual({
				before: asStored({ n: 10 }),
				after: asStored({ n: 11 }),
			});
		});

		it("ends a record at exactly its lifetime, a change keeping it", async () => {
			const place = await open();
			const key = fresh();
			await place.roundTrips.save(key, asStored({ n: 1 }), 1000);
			place.advance(500);
			await place.roundTrips.update(key, plus);
			place.advance(499);
			expect(await read(place.roundTrips, key)).toBeDefined();
			place.advance(1);
			expect(await read(place.roundTrips, key)).toBeUndefined();
		});

		it("never gives a round trip's cookie to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [cookie, kept] = [fresh(), fresh()];
			await place.roundTrips.save(cookie, asStored({ kept }), 60_000);
			await place.roundTrips.update(cookie, (record) => ({ value: record }));
			expect([holds(kept), holds(cookie)]).toEqual([true, false]);
		});

		it("keeps a change whose answer was lost, through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			await place.roundTrips.save(key, asStored({ n: 1 }), 60_000);
			lose();
			expect((await place.roundTrips.update(key, plus))?.after).toEqual(asStored({ n: 2 }));
			await failover();
			expect(await read(place.roundTrips, key)).toEqual(asStored({ n: 2 }));
		});
	});
}
