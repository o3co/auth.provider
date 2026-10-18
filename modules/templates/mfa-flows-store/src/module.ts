import { defineModule } from "@mod/kernel";
import {
	type StoredTransaction,
	transactionListings,
	type transactionListingsNeeds,
	transactionStore,
	type transactionStoreNeeds,
	transactionsPerHolder,
} from "@mod/mfa-flows";
import { keyedSetsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need mfa-flows states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof transactionStoreNeeds, Guarantee | typeof secretRecordsIn>;
const transactions: Space = {
	name: "mfa-flows-store.transactions",
	guarantees: Object.values(guaranteeFor),
};
/** Each need of the listings, as the guarantee their space declares; members are digests, so no secret names them. */
const listedGuaranteeFor = {
	...guaranteeFor,
	readsConfirmed: "confirmed-reads",
} satisfies Record<keyof typeof transactionListingsNeeds, Guarantee>;
const listings: Space = {
	name: "mfa-flows-store.transaction-listings",
	guarantees: Object.values(listedGuaranteeFor),
};

export default defineModule({ name: "mfa-flows-store" }, (m) => [
	m.contribute(spaces).by(() => transactions),
	m.contribute(spaces).by(() => listings),
	m.provide(transactionStore).by(async (c) => {
		const place = { store: await c.get(store), space: transactions, log: c.log, random: c.random };
		const records = recordsFor<StoredTransaction>(place);
		return { save: records.create, read: records.read, update: records.change };
	}),
	m.provide(transactionListings).by(async (c) =>
		keyedSetsIn({
			store: await c.get(store),
			space: listings,
			log: c.log,
			random: c.random,
			cap: transactionsPerHolder,
			clock: c.clock,
		}),
	),
]);
