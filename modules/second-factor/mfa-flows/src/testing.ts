import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { written } from "./section.ts";
import type { StoredTransaction, TransactionStore } from "./store.ts";

export type FlowSettings = z.input<typeof written>;

export function flowsConfig(settings: Partial<FlowSettings> = {}) {
	return { "mfa-flows": { ...settings } };
}

/** A place that keeps mfa-flows' transactions, as one implementation of its store interface offers it. */
export interface TransactionPlace {
	readonly transactions: TransactionStore;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `key` writes, another writer changes its transaction as given. */
	raceNextUpdate(key: string, change: (record: StoredTransaction) => StoredTransaction): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where what the place was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/** What mfa-flows needs from any implementation: transactions kept whole and once, for exactly their lifetime, through faults. */
export function transactionStoreContract(
	name: string,
	open: () => Promise<TransactionPlace>,
): void {
	let n = 0;
	const fresh = () => `t-${++n}-${Math.random().toString(36).slice(2)}`;
	const asStored = (value: object) => value as unknown as StoredTransaction;
	const counted = (record: StoredTransaction) => (record as unknown as { n: number }).n;
	const plus = (by: number) => (record: StoredTransaction) => ({
		value: asStored({ n: counted(record) + by }),
	});

	describe(`mfa-flows' store interface: ${name}`, () => {
		it("keeps a transaction whole and once per key, whatever it holds", async () => {
			const { transactions } = await open();
			const key = fresh();
			const odd = asStored({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await transactions.save(key, odd, 60_000)).toBe("created");
			expect(await transactions.save(key, asStored({ n: 1 }), 60_000)).toBe("exists");
			expect(await transactions.read(key)).toEqual(odd);
			expect(await transactions.update(key, () => undefined)).toEqual({ before: odd, after: odd });
			expect(await transactions.update(fresh(), plus(1))).toBeUndefined();
			expect(await transactions.read(fresh())).toBeUndefined();
		});

		it("changes a transaction only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const key = fresh();
			await place.transactions.save(key, asStored({ n: 1 }), 60_000);
			expect(await place.transactions.update(key, plus(1))).toEqual({
				before: asStored({ n: 1 }),
				after: asStored({ n: 2 }),
			});
			place.raceNextUpdate(key, (record) => asStored({ n: counted(record) * 10 }));
			expect((await place.transactions.update(key, plus(1)))?.after).toEqual(asStored({ n: 21 }));
		});

		it("ends a transaction at exactly the lifetime it was saved with, however it changed", async () => {
			const place = await open();
			const key = fresh();
			await place.transactions.save(key, asStored({ n: 1 }), 1000);
			place.advance(999);
			await place.transactions.update(key, plus(1));
			expect(await place.transactions.read(key)).toEqual(asStored({ n: 2 }));
			place.advance(1);
			expect(await place.transactions.read(key)).toBeUndefined();
			expect(await place.transactions.update(key, plus(1))).toBeUndefined();
			expect(await place.transactions.save(key, asStored({ n: 3 }), 1000)).toBe("created");
		});

		it("never gives a transaction's identifier to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [id, kept] = [fresh(), fresh()];
			await place.transactions.save(id, asStored({ kept }), 60_000);
			await place.transactions.read(id);
			await place.transactions.update(id, (record) => ({ value: record }));
			expect([holds(kept), holds(id)]).toEqual([true, false]);
		});

		it("keeps transactions through a restart and through memory pressure", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const key = fresh();
			await place.transactions.save(key, asStored({ n: 1 }), 60_000);
			await restart();
			await pressMemory();
			expect(await place.transactions.read(key)).toEqual(asStored({ n: 1 }));
		});

		it("settles writes whose answers were lost, and keeps them through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const key = fresh();
			lose();
			expect(await place.transactions.save(key, asStored({ n: 1 }), 60_000)).toBe("created");
			lose();
			expect((await place.transactions.update(key, plus(1)))?.after).toEqual(asStored({ n: 2 }));
			await failover();
			expect(await place.transactions.read(key)).toEqual(asStored({ n: 2 }));
		});
	});
}
