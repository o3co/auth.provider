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
	type NameStoreNeeds,
	type StoredContacts,
	type StoredLink,
	type StoredName,
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
/** Each need users states for its names' own records, mapped as for links: a dropped one fails the type. */
const nameGuaranteeFor = {
	neverEvicted: guaranteeFor.neverEvicted,
	survivesCrash: guaranteeFor.survivesCrash,
	survivesFailover: guaranteeFor.survivesFailover,
	confirmedReads: guaranteeFor.confirmedReads,
} satisfies Record<keyof NameStoreNeeds, Guarantee>;
const links: Space = { name: "users-store.links", guarantees: Object.values(guaranteeFor) };
/** IdP names' records, apart from the links: they hold no subject's data. */
const names: Space = {
	name: "users-store.names",
	guarantees: Object.values(nameGuaranteeFor),
	subjectData: "none",
};
const contacts: Space = {
	name: "users-store.contacts",
	guarantees: Object.values(contactGuaranteeFor),
};

export default defineModule({ name: "users-store", replicaSafe: true, takes: [store] }, (m) => [
	m.contribute(spaces).by(() => links),
	m.contribute(spaces).by(() => contacts),
	m.contribute(spaces).by(() => names),
	m.provide(linkStore).by(async (c): Promise<LinkStore> => {
		const held = await c.get(store);
		const place = { store: held, space: links, log: c.log, random: c.random };
		const records = recordsIn<StoredLink>(place);
		const named = recordsIn<StoredName>({ ...place, space: names });
		return {
			save: records.create,
			read: records.read,
			update: records.change,
			names: { save: named.create, read: named.read, update: named.change },
			// The link space keeps names' records raw until its records are indexed.
			unowned: (key, record, lifetimeMs) =>
				records.create(key, record as unknown as StoredLink, lifetimeMs),
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
