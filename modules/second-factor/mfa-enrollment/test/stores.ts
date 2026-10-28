import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import {
	type StoredTransaction,
	type TransactionListings,
	type TransactionStore,
	transactionListings,
	transactionStore,
	transactionsPerHolder,
} from "@mod/mfa-flows";
import { memoryRecords } from "@mod/records/testing";

/** mfa-flows' transaction store on the records stand-in, its lifetimes on the given clock, behind a switch. */
export function memoryTransactions(now: () => number) {
	const stand = memoryRecords<StoredTransaction>(now, { shards: 1, perShard: 1 });
	let before: (() => Promise<void>) | undefined;
	const saves = { count: 0 };
	const down = unavailableSwitch<TransactionStore>("transaction store");
	const transactions = down.wrap({
		save: (key, record, lifetimeMs) => {
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
	const listings = listingsDown.wrap(stand.keyedSets(transactionsPerHolder));
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
		peek: stand.peek,
		raceNextChange: stand.raceNextChange,
	};
}
