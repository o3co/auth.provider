import { defineModule } from "@mod/kernel";
import { secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import {
	heldLoginStore,
	type heldLoginStoreNeeds,
	type StoredHeldLogin,
} from "@mod/upstream-handoff";

/** Each need upstream-handoff states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof heldLoginStoreNeeds, Guarantee | typeof secretRecordsIn>;
const heldLogins: Space = {
	name: "upstream-handoff-store.held-logins",
	guarantees: Object.values(guaranteeFor),
};

export default defineModule({ name: "upstream-handoff-store", takes: [store] }, (m) => [
	m.contribute(spaces).by(() => heldLogins),
	m.provide(heldLoginStore).by(async (c) => {
		const place = { store: await c.get(store), space: heldLogins, log: c.log, random: c.random };
		const records = recordsFor<StoredHeldLogin>(place);
		return { save: records.create, update: records.change, remove: records.remove };
	}),
]);
