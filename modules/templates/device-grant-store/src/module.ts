import {
	deviceStore,
	type deviceStoreNeeds,
	type StoredDevice,
	userCodes,
} from "@mod/device-grant";
import { defineModule } from "@mod/kernel";
import { recordsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need device-grant states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof deviceStoreNeeds, Guarantee | typeof secretRecordsIn>;
const guarantees = Object.values(guaranteeFor);
const devices: Space = { name: "device-grant-store.devices", guarantees };
const codes: Space = { name: "device-grant-store.user-codes", guarantees };

export default defineModule(
	{ name: "device-grant-store", replicaSafe: true, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => devices),
		m.contribute(spaces).by(() => codes),
		m.provide(deviceStore).by(async (c) => {
			const place = { store: await c.get(store), space: devices, log: c.log, random: c.random };
			const records = recordsFor<StoredDevice>(place);
			return {
				nameOf: records.nameOf,
				save: records.named.create,
				read: records.named.read,
				update: records.named.change,
			};
		}),
		m.provide(userCodes).by(async (c) => {
			const place = { store: await c.get(store), space: codes, log: c.log, random: c.random };
			const records = recordsIn<string>(place);
			return { save: records.create, read: records.read };
		}),
	],
);
