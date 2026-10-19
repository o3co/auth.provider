import { reauthStore, type reauthStoreNeeds, type StoredReauth } from "@mod/authorize";
import { defineModule } from "@mod/kernel";
import { type StoredReauth as KeptReauth, reauthStore as reauthsKept } from "@mod/reauth";
import { secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need authorize states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof reauthStoreNeeds, Guarantee | typeof secretRecordsIn>;
const reauths: Space = { name: "authorize-store.reauths", guarantees: Object.values(guaranteeFor) };

export default defineModule({ name: "authorize-store" }, (m) => [
	m.contribute(spaces).by(() => reauths),
	m.provide(reauthStore).by(async (c) => {
		const place = { store: await c.get(store), space: reauths, log: c.log, random: c.random };
		const records = recordsFor<StoredReauth>(place);
		return { save: records.create, update: records.change };
	}),
	// The same records, for \`reauth\`, which takes them over from authorize: one space for both.
	m.provide(reauthsKept).by(async (c) => {
		const place = { store: await c.get(store), space: reauths, log: c.log, random: c.random };
		const records = recordsFor<KeptReauth>(place);
		return { save: records.create, update: records.change };
	}),
]);
