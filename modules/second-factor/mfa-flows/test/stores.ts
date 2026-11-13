import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type StoredTransaction,
	type TransactionListings,
	type TransactionStore,
	transactionListings,
	transactionStore,
} from "../src/store.ts";

/** The live transactions a holder keeps here, as mfa-flows-store keeps them by default. */
export const perHolder = 5;

/** mfa-flows' transaction store on the records stand-in, its lifetimes on the given clock, behind a switch. */
export function memoryTransactions(now: () => number) {
	const stand = memoryRecords<StoredTransaction>(now, { shards: 1, perShard: 1 });
	let before: (() => Promise<void>) | undefined;
	const saves = { count: 0 };
	const down = unavailableSwitch<TransactionStore>("transaction store");
	/** Subjects erased: a transaction saved, or a listing added, for one is answered `erased`, as a Store that erases does. */
	const erased = { transactions: new Set<string>(), listings: new Set<string>() };
	const transactions = down.wrap({
		save: async (key, record, lifetimeMs, subject) => {
			if (erased.transactions.has(subject)) return "erased";
			saves.count++;
			return stand.records.create(key, record, lifetimeMs);
		},
		read: stand.records.read,
		update: async (key, change) => {
			const run = before;
			before = undefined;
			await run?.();
			return stand.records.change(key, change);
		},
	});
	const listingsDown = unavailableSwitch<TransactionListings>("transaction listings");
	const sets = stand.keyedSets(perHolder);
	const listings = listingsDown.wrap({
		...sets,
		add: async (key, member, lifetimeMs, subject) =>
			erased.listings.has(subject) ? "erased" : sets.add(key, member, lifetimeMs),
	});
	const module = defineModule({ name: "transaction-store", replicaSafe: false, takes: [] }, (m) => [
		m.provide(transactionStore).by(() => transactions),
		m.provide(transactionListings).by(() => listings),
	]);
	/** Runs `run` before the next update, as another request would. */
	const beforeNextUpdate = (run: () => Promise<void>) => {
		before = run;
	};
	return {
		module,
		transactions,
		listings,
		beforeNextUpdate,
		down,
		listingsDown,
		/** How many transactions were saved. */
		saves,
		erased,
		peek: stand.peek,
		raceNextChange: stand.raceNextChange,
	};
}
