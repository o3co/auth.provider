import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import {
	type ContactStore,
	contactStore,
	type contactStoreNeeds,
	type LinkStore,
	linkStore,
	type linkStoreNeeds,
	type StoredContacts,
	type StoredLink,
} from "@mod/users";

/** Each need users states for its links, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof linkStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
/** Each need users states for its contacts, mapped as for links. */
const contactGuaranteeFor: Record<keyof typeof contactStoreNeeds, Guarantee> = {
	neverEvicted: guaranteeFor.neverEvicted,
	survivesCrash: guaranteeFor.survivesCrash,
	survivesFailover: guaranteeFor.survivesFailover,
};
const links: Space = { name: "users-store.links", guarantees: Object.values(guaranteeFor) };
const contacts: Space = {
	name: "users-store.contacts",
	guarantees: Object.values(contactGuaranteeFor),
};

export default defineModule({ name: "users-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => links),
	m.contribute(spaces).by(() => contacts),
	m.provide(linkStore).by(async (c): Promise<LinkStore> => {
		const place = { store: await c.get(store), space: links, log: c.log, random: c.random };
		const records = recordsIn<StoredLink>(place);
		return {
			save: records.create,
			read: records.read,
			update: records.change,
		};
	}),
	m.provide(contactStore).by(async (c): Promise<ContactStore> => {
		const place = { store: await c.get(store), space: contacts, log: c.log, random: c.random };
		const records = recordsIn<StoredContacts>(place);
		return {
			save: records.create,
			read: records.read,
			update: records.change,
		};
	}),
]);
