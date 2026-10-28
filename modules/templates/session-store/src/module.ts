import { type BuildContext, defineModule } from "@mod/kernel";
import { deferredIn, keyedSetsIn, recordsIn, secretRecordsIn } from "@mod/records";
import {
	closingList,
	cookieIndex,
	type cookieIndexNeeds,
	type StoredSession,
	sessionStore,
	type sessionStoreNeeds,
	subjectSessions,
	type subjectSessionsNeeds,
} from "@mod/session-lifecycle";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { section } from "./section.ts";

/** Each need session-lifecycle states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof sessionStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
};
const guarantees = Object.values(guaranteeFor);
/** Each need the cookie index states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: cookieRecordsFor, ...cookieGuaranteeFor } = {
	...guaranteeFor,
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof cookieIndexNeeds, Guarantee | typeof secretRecordsIn>;
const sessions: Space = { name: "session-store.sessions", guarantees };
const cookies: Space = {
	name: "session-store.cookies",
	guarantees: Object.values(cookieGuaranteeFor),
};
const closings: Space = { name: "session-store.closings", guarantees };
const { neverEvicted, survivesCrash, survivesFailover } = guaranteeFor;
const listedGuaranteeFor: Record<keyof typeof subjectSessionsNeeds, Guarantee> = {
	neverEvicted,
	survivesCrash,
	survivesFailover,
	readsConfirmed: guaranteeFor.readsConfirmed,
};
const subjects: Space = {
	name: "session-store.subjects",
	guarantees: Object.values(listedGuaranteeFor),
};

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

// Safe on many instances given the same `closing-shards` and `closings-per-shard` on each
// (deployment-guarantees, Several instances): closing sessions go to a shard by their hash, and a
// sweep walks only the shards it counts.
export default defineModule(
	{ name: "session-store", replicaSafe: true, section, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => sessions),
		m.contribute(spaces).by(() => cookies),
		m.contribute(spaces).by(() => closings),
		m.contribute(spaces).by(() => subjects),
		m.provide(sessionStore).by(async (c) => {
			const records = recordsIn<StoredSession>(await placeIn(c, sessions));
			return { save: records.create, read: records.read, update: records.change };
		}),
		m.provide(cookieIndex).by(async (c) => {
			const records = cookieRecordsFor<string>(await placeIn(c, cookies));
			return { save: records.create, read: records.read, remove: records.remove };
		}),
		m.provide(subjectSessions).by(async (c) =>
			keyedSetsIn({
				...(await placeIn(c, subjects)),
				cap: c.section["sessions-per-subject"],
				clock: c.clock,
			}),
		),
		m.provide(closingList).by(async (c) =>
			deferredIn({
				...(await placeIn(c, closings)),
				shards: c.section["closing-shards"],
				perShard: c.section["closings-per-shard"],
			}),
		),
	],
);
