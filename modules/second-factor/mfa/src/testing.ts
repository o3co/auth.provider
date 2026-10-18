import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type { FactorStore, StoredFactors } from "./store.ts";

export type MfaSettings = z.input<typeof section>;

export function mfaConfig(settings: Partial<MfaSettings> = {}) {
	return { mfa: { mode: "optional", ...settings } };
}

/** A place that keeps mfa's factor lists, as one implementation of its store interface offers it. */
export interface FactorPlace {
	readonly factors: FactorStore;
	/** Moves the place's clock on. */
	advance(ms: number): void;
	/** Before the next update of `key` writes, another writer changes its list as given. */
	raceNextUpdate(key: string, change: (record: StoredFactors) => StoredFactors): void;
	/** Where reads can meet unconfirmed writes: runs `during` as the next save takes effect, unconfirmed. */
	readonly duringNextSave?: (during: () => Promise<void>) => void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/** What mfa needs from any implementation: lists kept whole, without end, and read as a failover keeps them. */
export function factorStoreContract(name: string, open: () => Promise<FactorPlace>): void {
	let n = 0;
	const fresh = () => `f-${++n}-${Math.random().toString(36).slice(2)}`;
	const asStored = (value: object) => value as unknown as StoredFactors;
	const counted = (record: StoredFactors) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredFactors) => ({
		value: asStored({ n: counted(record) + by }),
	});

	describe(`mfa's store interface: ${name}`, () => {
		it("keeps a list whole and once per key, whatever it holds", async () => {
			const { factors } = await open();
			const key = fresh();
			const odd = asStored({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await factors.save(key, odd, "endless")).toBe("created");
			expect(await factors.save(key, asStored({ n: 1 }), "endless")).toBe("exists");
			expect(await factors.read(key)).toEqual(odd);
			expect(await factors.update(key, () => undefined)).toEqual({ before: odd, after: odd });
			expect(await factors.update(fresh(), plus(1))).toBeUndefined();
			expect(await factors.read(fresh())).toBeUndefined();
		});

		it("changes a list only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const key = fresh();
			await place.factors.save(key, asStored({ n: 1 }), "endless");
			expect(await place.factors.update(key, plus(1))).toEqual({
				before: asStored({ n: 1 }),
				after: asStored({ n: 2 }),
			});
			place.raceNextUpdate(key, (record) => asStored({ n: counted(record) * 10 }));
			expect((await place.factors.update(key, plus(1)))?.after).toEqual(asStored({ n: 21 }));
		});

		it("walks the keys it keeps, over pages", async () => {
			const place = await open();
			const keys = Array.from({ length: 120 }, fresh);
			for (const key of keys) await place.factors.save(key, asStored({ n: 1 }), "endless");
			const seen = new Set<string>();
			let cursor: string | undefined;
			do {
				const page = await place.factors.scan(cursor);
				for (const key of page.keys) seen.add(key);
				cursor = page.cursor;
			} while (cursor !== undefined);
			expect(keys.filter((key) => !seen.has(key))).toEqual([]);
		});

		it("keeps a list without end, changed or not", async () => {
			const place = await open();
			const [kept, changed] = [fresh(), fresh()];
			await place.factors.save(kept, asStored({ n: 1 }), "endless");
			await place.factors.save(changed, asStored({ n: 1 }), "endless");
			await place.factors.update(changed, plus(1));
			place.advance(10 * 365 * 86_400_000);
			expect(await place.factors.read(kept)).toEqual(asStored({ n: 1 }));
			expect(await place.factors.read(changed)).toEqual(asStored({ n: 2 }));
		});

		it("keeps lists, and each change to them, through a restart and through memory pressure", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const key = fresh();
			await place.factors.save(key, asStored({ n: 1 }), "endless");
			// As a proof's state is changed: a used step must not come back.
			await place.factors.update(key, plus(1));
			await restart();
			await pressMemory();
			expect(await place.factors.read(key)).toEqual(asStored({ n: 2 }));
		});

		it("settles writes whose answers were lost, and keeps them through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			lose();
			expect(await place.factors.save(key, asStored({ n: 1 }), "endless")).toBe("created");
			lose();
			expect((await place.factors.update(key, plus(1)))?.after).toEqual(asStored({ n: 2 }));
			await failover();
			expect(await place.factors.read(key)).toEqual(asStored({ n: 2 }));
		});

		// The writer gives up once the clock passes its patience, so only the read could have kept it.
		it("reads a list another request wrote only as a failover keeps it", async (context) => {
			const place = await open();
			const { duringNextSave, failover } = place;
			if (!duringNextSave || !failover) return context.skip();
			const key = fresh();
			let seen: StoredFactors | undefined;
			duringNextSave(async () => {
				seen = await place.factors.read(key);
				await failover();
				place.advance(60_000);
			});
			await place.factors.save(key, asStored({ n: 1 }), "endless").catch(() => undefined);
			expect(seen).toEqual(asStored({ n: 1 }));
			expect(await place.factors.read(key)).toEqual(seen);
		});
	});
}
