import { contract, defineModule, optional, probes } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Json, type Space, spaces, store, storeControl } from "@mod/store";
import { indexSpaceOf, phasedRecordsIn, subjectRecordsPhase } from "@mod/subject-records";
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
/** Links, many a subject's, keyed by upstream identity: kept indexed by their subject, erased by users. */
const links: Space = {
	name: "users-store.links",
	guarantees: Object.values(guaranteeFor),
	subjectData: "online-indexed",
	erasedBy: "users",
};
/** Verified contacts, one record a subject's, keyed by the subject: erased by users. */
const contacts: Space = {
	name: "users-store.contacts",
	guarantees: Object.values(contactGuaranteeFor),
	subjectData: "online-keyed",
	erasedBy: "users",
};
/** IdP names' records, apart from the links: they hold no subject's data. */
const names: Space = {
	name: "users-store.names",
	guarantees: Object.values(nameGuaranteeFor),
	subjectData: "none",
};

/** Links and contacts over the one phase this process reads, and names' records apart. */
const placed = contract<{
	readonly links: Awaited<ReturnType<typeof phasedRecordsIn<StoredLink>>>;
	readonly contacts: Awaited<ReturnType<typeof phasedRecordsIn<StoredContacts>>>;
	readonly names: ReturnType<typeof recordsIn<StoredName>>;
}>("users-store.placed");

export default defineModule(
	{ name: "users-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => links),
		m.contribute(spaces).by(() => indexSpaceOf(links)),
		m.contribute(spaces).by(() => contacts),
		m.contribute(spaces).by(() => indexSpaceOf(contacts)),
		m.contribute(spaces).by(() => names),
		m.provide(placed).by(async (c) => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			const held = await c.get(store);
			const at = (space: Space) => ({
				store: held,
				space,
				index: indexSpaceOf(space),
				log: c.log,
				random: c.random,
			});
			return {
				links: await phasedRecordsIn<StoredLink>(at(links), phase, "users-store", c.refuse),
				contacts: await phasedRecordsIn<StoredContacts>(
					at(contacts),
					phase,
					"users-store",
					c.refuse,
				),
				names: recordsIn<StoredName>({ store: held, space: names, log: c.log, random: c.random }),
			};
		}),
		m.provide(linkStore).by(async (c): Promise<LinkStore> => {
			const { links: records, names: named } = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				remove: records.remove,
				erase: records.erase,
				migrate: records.migrate,
				names: { save: named.create, read: named.read, update: named.change },
				// A name's record holds no subject: raw in the link space until its records are indexed.
				unowned: (key, record, lifetimeMs) =>
					records.unowned(key, record as unknown as Json, lifetimeMs),
			};
		}),
		m.provide(contactStore).by(async (c): Promise<ContactStore> => {
			const { contacts: records } = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const { links: l, contacts: k } = await c.get(placed);
			return {
				name: "users-store.phase",
				check: async () => {
					await l.ready();
					await k.ready();
				},
			};
		}),
	],
);
