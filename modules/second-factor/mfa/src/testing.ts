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
	/** Where another writer can come between: before the next list and claim changed together are written, it changes the record at `key` as given. */
	readonly raceNextTogether?: (
		key: string,
		change: (record: StoredFactors) => StoredFactors,
	) => void;
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

		it("changes a list and a claim as one where it can, giving the change the records it watched", async (ctx) => {
			const { factors } = await open();
			const together = factors.updateTogether?.bind(factors);
			if (!together) {
				ctx.skip();
				return;
			}
			const [list, claimKey, owner] = [fresh(), fresh(), fresh()];
			await factors.save(owner, asStored({ n: 7 }), "endless");
			const seen: unknown[] = [];
			const first = await together(list, claimKey, {
				watch: () => [owner],
				change: (current, claim, watched) => {
					seen.push([current, claim, watched]);
					return { list: { value: asStored({ n: 1 }) }, claim: { value: asStored({ n: 2 }) } };
				},
			});
			expect(seen).toEqual([[undefined, undefined, [asStored({ n: 7 })]]]);
			expect(first).toEqual({
				list: { before: undefined, after: asStored({ n: 1 }) },
				claim: { before: undefined, after: asStored({ n: 2 }) },
			});
			expect([await factors.read(list), await factors.read(claimKey)]).toEqual([
				asStored({ n: 1 }),
				asStored({ n: 2 }),
			]);
			const kept = await together(list, claimKey, {
				watch: () => [],
				change: () => ({ list: plus(1)(asStored({ n: 1 })) }),
			});
			expect(kept).toEqual({
				list: { before: asStored({ n: 1 }), after: asStored({ n: 2 }) },
				claim: { before: asStored({ n: 2 }), after: asStored({ n: 2 }) },
			});
			expect(await factors.read(claimKey)).toEqual(asStored({ n: 2 }));
		});

		it("changes a list and a claim again where another writer changes what it watched, or the claim's owner, first", async (ctx) => {
			const { factors, raceNextTogether: race } = await open();
			const together = factors.updateTogether?.bind(factors);
			if (!together || !race) {
				ctx.skip();
				return;
			}
			const [list, claimKey, ann, bob] = [fresh(), fresh(), fresh(), fresh()];
			await factors.save(ann, asStored({ n: 1 }), "endless");
			await factors.save(bob, asStored({ n: 2 }), "endless");
			await factors.save(claimKey, asStored({ owner: ann }), "endless");
			const ownerOf = (claim: StoredFactors | undefined) =>
				(claim as unknown as { owner?: string } | undefined)?.owner;
			const watchedKeys: string[][] = [];
			const seen: unknown[] = [];
			// The list follows the claim's owner, unless the owner's list holds 2: then nothing is written.
			const run = () =>
				together(list, claimKey, {
					watch: (_list, claim) => {
						const owner = ownerOf(claim);
						const keys = owner ? [owner] : [];
						watchedKeys.push(keys);
						return keys;
					},
					change: (_list, _claim, [owner]) => {
						seen.push(owner);
						const held = owner ? counted(owner) : 0;
						return held === 2 ? {} : { list: { value: asStored({ n: 100 + held }) } };
					},
				});
			race(ann, () => asStored({ n: 10 }));
			expect((await run()).list.after).toEqual(asStored({ n: 110 }));
			expect(seen).toEqual([asStored({ n: 1 }), asStored({ n: 10 })]);
			watchedKeys.length = 0;
			seen.length = 0;
			race(claimKey, () => asStored({ owner: bob }));
			const kept = await run();
			expect(watchedKeys).toEqual([[ann], [bob]]);
			expect(seen).toEqual([asStored({ n: 10 }), asStored({ n: 2 })]);
			expect(kept.list).toEqual({ before: asStored({ n: 110 }), after: asStored({ n: 110 }) });
			expect(await factors.read(claimKey)).toEqual(asStored({ owner: bob }));
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
