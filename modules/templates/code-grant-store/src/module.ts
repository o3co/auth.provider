import { codeStore, type codeStoreNeeds, type StoredCode, voidList } from "@mod/code-grant";
import { defineModule } from "@mod/kernel";
import { deferredIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { section } from "./section.ts";

/** Each need code-grant states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof codeStoreNeeds, Guarantee | typeof secretRecordsIn>;
const guarantees = Object.values(guaranteeFor);
const codes: Space = { name: "code-grant-store.codes", guarantees };
const voids: Space = { name: "code-grant-store.voids", guarantees };

export default defineModule({ name: "code-grant-store", section, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => codes),
	m.contribute(spaces).by(() => voids),
	m.provide(codeStore).by(async (c) => {
		const records = recordsFor<StoredCode>({
			store: await c.get(store),
			space: codes,
			log: c.log,
			random: c.random,
		});
		return { nameOf: records.nameOf, save: records.named.create, update: records.named.change };
	}),
	m.provide(voidList).by(async (c) =>
		deferredIn({
			store: await c.get(store),
			space: voids,
			log: c.log,
			random: c.random,
			shards: c.section["void-shards"],
			perShard: c.section["voids-per-shard"],
		}),
	),
]);
