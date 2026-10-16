import {
	type StoredTransaction,
	transactionStore,
	type transactionStoreNeeds,
} from "@mod/federation";
import { defineModule } from "@mod/kernel";
import { secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need federation states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof transactionStoreNeeds, Guarantee | typeof secretRecordsIn>;
const transactions: Space = {
	name: "federation-store.transactions",
	guarantees: Object.values(guaranteeFor),
};

export default defineModule({ name: "federation-store" }, (m) => [
	m.contribute(spaces).by(() => transactions),
	m.provide(transactionStore).by(async (c) => {
		const place = { store: await c.get(store), space: transactions, log: c.log, random: c.random };
		const records = recordsFor<StoredTransaction>(place);
		return { save: records.create, update: records.change, remove: records.remove };
	}),
]);
