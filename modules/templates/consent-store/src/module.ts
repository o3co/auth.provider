import {
	askStore,
	type askStoreNeeds,
	grantStore,
	type grantStoreNeeds,
	type StoredAsk,
	type StoredGrant,
} from "@mod/consent";
import { defineModule } from "@mod/kernel";
import { recordsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need consent states for its grants, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof grantStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
/** Each need consent states for its asks, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: askRecordsFor, ...askGuaranteeFor } = {
	neverEvicted: guaranteeFor.neverEvicted,
	survivesCrash: guaranteeFor.survivesCrash,
	survivesFailover: guaranteeFor.survivesFailover,
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof askStoreNeeds, Guarantee | typeof secretRecordsIn>;
const grants: Space = { name: "consent-store.grants", guarantees: Object.values(guaranteeFor) };
const asks: Space = { name: "consent-store.asks", guarantees: Object.values(askGuaranteeFor) };

export default defineModule({ name: "consent-store" }, (m) => [
	m.contribute(spaces).by(() => grants),
	m.contribute(spaces).by(() => asks),
	m.provide(grantStore).by(async (c) => {
		const place = { store: await c.get(store), space: grants, log: c.log, random: c.random };
		const records = recordsIn<StoredGrant>(place);
		return { save: records.create, read: records.read, update: records.change };
	}),
	m.provide(askStore).by(async (c) => {
		const place = { store: await c.get(store), space: asks, log: c.log, random: c.random };
		const records = askRecordsFor<StoredAsk>(place);
		return { save: records.create, read: records.read, update: records.change };
	}),
]);
