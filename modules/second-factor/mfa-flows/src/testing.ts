import { describe, expect, it } from "vitest";
import type { z } from "zod";
import { section } from "./section.ts";
import type { StoredTransaction, TransactionListings, TransactionStore } from "./store.ts";

export type FlowSettings = z.input<typeof section>;

export function flowsConfig(settings: Partial<FlowSettings> = {}) {
	return { "mfa-flows": { ...settings } };
}

/** The keys of this package's section, so a test can tell its settings from `mfa`'s. */
export const flowKeys: readonly string[] = Object.keys(section.shape);

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
			expect(await transactions.save(key, odd, 60_000, "alice")).toBe("created");
			expect(await transactions.save(key, asStored({ n: 1 }), 60_000, "alice")).toBe("exists");
			expect(await transactions.read(key)).toEqual(odd);
			expect(await transactions.update(key, () => undefined)).toEqual({ before: odd, after: odd });
			expect(await transactions.update(fresh(), plus(1))).toBeUndefined();
			expect(await transactions.read(fresh())).toBeUndefined();
		});

		it("changes a transaction only from what it holds, again after a racing writer", async () => {
			const place = await open();
			const key = fresh();
			await place.transactions.save(key, asStored({ n: 1 }), 60_000, "alice");
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
			await place.transactions.save(key, asStored({ n: 1 }), 1000, "alice");
			place.advance(999);
			await place.transactions.update(key, plus(1));
			expect(await place.transactions.read(key)).toEqual(asStored({ n: 2 }));
			place.advance(1);
			expect(await place.transactions.read(key)).toBeUndefined();
			expect(await place.transactions.update(key, plus(1))).toBeUndefined();
			expect(await place.transactions.save(key, asStored({ n: 3 }), 1000, "alice")).toBe("created");
		});

		it("never gives a transaction's identifier to what the place holds, in clear", async (context) => {
			const place = await open();
			const { holds } = place;
			if (!holds) return context.skip();
			const [id, kept] = [fresh(), fresh()];
			await place.transactions.save(id, asStored({ kept }), 60_000, "alice");
			await place.transactions.read(id);
			await place.transactions.update(id, (record) => ({ value: record }));
			expect([holds(kept), holds(id)]).toEqual([true, false]);
		});

		it("refuses, where the store erases, every transaction saved for a subject it erased, and only for that subject", async (context) => {
			const { transactions } = await open();
			if (!transactions.erase) return context.skip();
			await transactions.save(fresh(), asStored({ n: 1 }), 60_000, "erin");
			const report = await transactions.erase.call(
				transactions,
				"erin",
				new AbortController().signal,
			);
			// A Store that erases nothing now (its records not indexed yet) says so, and fences nothing.
			if (report.kind === "stopped") return context.skip();
			expect(["erased", "fenced"]).toContain(report.kind);
			expect(await transactions.save(fresh(), asStored({ n: 2 }), 60_000, "erin")).toBe("erased");
			expect(await transactions.save(fresh(), asStored({ n: 3 }), 60_000, "finn")).toBe("created");
		});

		it("keeps transactions through a restart and through memory pressure", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const key = fresh();
			await place.transactions.save(key, asStored({ n: 1 }), 60_000, "alice");
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
			expect(await place.transactions.save(key, asStored({ n: 1 }), 60_000, "alice")).toBe(
				"created",
			);
			lose();
			expect((await place.transactions.update(key, plus(1)))?.after).toEqual(asStored({ n: 2 }));
			await failover();
			expect(await place.transactions.read(key)).toEqual(asStored({ n: 2 }));
		});
	});
}

/** A place that keeps each holder's live transactions, as one implementation of that store interface offers it. */
export interface ListingPlace {
	readonly listings: TransactionListings;
	/** How many live transactions a holder's listing keeps, as the place was given; unset, 5. */
	readonly cap?: number;
	/** Moves the place's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the place replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the place can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
}

/** What mfa-flows needs of the listings: each member for its lifetime, at most five a holder, kept through faults. */
export function transactionListingsContract(name: string, open: () => Promise<ListingPlace>): void {
	let n = 0;
	const fresh = () => `l-${++n}-${Math.random().toString(36).slice(2)}`;
	const membersOf = async (listings: TransactionListings, key: string) =>
		(await listings.members(key)).map(({ member }) => member).sort();

	/** What an add answered, for a subject the place has not erased. */
	const listedOf = (added: Awaited<ReturnType<TransactionListings["add"]>>) => {
		if (typeof added === "string") throw new Error(`listed as ${added}`);
		return added;
	};

	describe(`mfa-flows' listings: ${name}`, () => {
		it("lists a holder's members each for its lifetime, until one is removed, apart from other holders", async () => {
			const { listings, advance } = await open();
			const [key, other, ending, lasting] = [fresh(), fresh(), fresh(), fresh()];
			expect(listedOf(await listings.add(key, ending, 1000, "alice")).pushedOut).toEqual([]);
			await listings.add(key, lasting, 60_000, "alice");
			await listings.add(other, ending, 60_000, "alice");
			expect(await membersOf(listings, key)).toEqual([ending, lasting].sort());
			advance(1000);
			expect(await membersOf(listings, key)).toEqual([lasting]);
			await listings.remove(key, lasting);
			await listings.remove(fresh(), lasting);
			expect(await membersOf(listings, key)).toEqual([]);
			expect(await membersOf(listings, other)).toEqual([ending]);
		});

		it("holds as many a holder as its cap: one more pushes out the one ending first, never the one added", async () => {
			// A place that gives no cap is held to 5, the cap every place kept before one could give it.
			const { listings, cap = 5 } = await open();
			const key = fresh();
			const kept = Array.from({ length: cap }, () => fresh());
			for (const [i, member] of kept.entries()) {
				expect(listedOf(await listings.add(key, member, 60_000 + i, "alice")).pushedOut).toEqual(
					[],
				);
			}
			// The one added ends before every one listed, yet stays.
			const added = fresh();
			expect(listedOf(await listings.add(key, added, 1000, "alice")).pushedOut).toEqual([kept[0]]);
			expect(await membersOf(listings, key)).toEqual([added, ...kept.slice(1)].sort());
		});

		it("refuses, where the listings erase, every add for a subject they erased, and only for that subject", async (context) => {
			const { listings } = await open();
			if (!listings.erase) return context.skip();
			const [key, other] = [fresh(), fresh()];
			await listings.add(key, fresh(), 60_000, "erin");
			const report = await listings.erase.call(listings, "erin", new AbortController().signal);
			// A Store that erases nothing now (its sets not indexed yet) says so, and fences nothing.
			if (report.kind === "stopped") return context.skip();
			expect(report).toMatchObject({ kind: "erased", removed: 1 });
			expect(await membersOf(listings, key)).toEqual([]);
			expect(await listings.add(key, fresh(), 60_000, "erin")).toBe("erased");
			expect(listedOf(await listings.add(other, fresh(), 60_000, "finn")).pushedOut).toEqual([]);
		});

		it("keeps members through a restart and through memory pressure", async (context) => {
			const place = await open();
			const { restart, pressMemory } = place;
			if (!restart || !pressMemory) return context.skip();
			const [key, member] = [fresh(), fresh()];
			await place.listings.add(key, member, 60_000, "alice");
			await restart();
			await pressMemory();
			expect(await membersOf(place.listings, key)).toEqual([member]);
		});

		it("settles an add whose answer was lost, and keeps it through a failover", async (context) => {
			const place = await open();
			const { loseNextAnswer: lose, failover } = place;
			if (!lose || !failover) return context.skip();
			const [key, member] = [fresh(), fresh()];
			lose();
			await place.listings.add(key, member, 60_000, "alice").catch(() => undefined);
			await place.listings.add(key, member, 60_000, "alice");
			await failover();
			expect(await membersOf(place.listings, key)).toEqual([member]);
		});
	});
}
