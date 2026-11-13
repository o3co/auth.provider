import { type BuildContext, contract, defineModule, optional, probes } from "@mod/kernel";
import { deferredIn, secretRecordsIn } from "@mod/records";
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
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedKeyedSetsIn,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
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
/** Sessions, each a subject's: kept indexed by it, erased by session-lifecycle, at the tombstone's floor. */
const sessions: Space = {
	name: "session-store.sessions",
	guarantees: [...new Set([...guarantees, ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "session-lifecycle",
};
const cookies: Space = {
	name: "session-store.cookies",
	guarantees: Object.values(cookieGuaranteeFor),
	subjectData: "none",
};
const closings: Space = { name: "session-store.closings", guarantees, subjectData: "none" };
const { neverEvicted, survivesCrash, survivesFailover } = guaranteeFor;
const listedGuaranteeFor: Record<keyof typeof subjectSessionsNeeds, Guarantee> = {
	neverEvicted,
	survivesCrash,
	survivesFailover,
	readsConfirmed: guaranteeFor.readsConfirmed,
};
/** Each subject's listed sessions, keyed by the subject itself: erased by session-lifecycle, at the floor. */
const subjects: Space = {
	name: "session-store.subjects",
	guarantees: [...new Set([...Object.values(listedGuaranteeFor), ...tombstoneFloor])],
	subjectData: "online-keyed",
	erasedBy: "session-lifecycle",
};

/** The sessions' records and the listings over the one phase this process reads once. */
const placed = contract<{
	readonly records: Awaited<ReturnType<typeof phasedRecordsIn<StoredSession>>>;
	readonly sets: Awaited<ReturnType<typeof phasedKeyedSetsIn>>;
}>("session-store.placed");

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
	{ name: "session-store", replicaSafe: true, section, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => sessions),
		m.contribute(spaces).by(() => indexSpaceOf(sessions)),
		m.contribute(spaces).by(() => cookies),
		m.contribute(spaces).by(() => closings),
		m.contribute(spaces).by(() => subjects),
		m.contribute(spaces).by(() => indexSpaceOf(subjects)),
		m.provide(placed).by(async (c) => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			return {
				records: await phasedRecordsIn<StoredSession>(
					{ ...(await placeIn(c, sessions)), index: indexSpaceOf(sessions) },
					phase,
					"session-store",
					c.refuse,
				),
				sets: await phasedKeyedSetsIn(
					{
						...(await placeIn(c, subjects)),
						index: indexSpaceOf(subjects),
						cap: c.section["sessions-per-subject"],
						clock: c.clock,
					},
					phase,
					"session-store",
					c.refuse,
				),
			};
		}),
		m.provide(sessionStore).by(async (c) => {
			const { records } = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		// Out of traffic until the phase reads for both: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const { records, sets } = await c.get(placed);
			return {
				name: "session-store.phase",
				check: async () => {
					await records.ready();
					await sets.ready();
				},
			};
		}),
		m.provide(cookieIndex).by(async (c) => {
			const records = cookieRecordsFor<string>(await placeIn(c, cookies));
			return { save: records.create, read: records.read, remove: records.remove };
		}),
		m.provide(subjectSessions).by(async (c) => {
			const { sets } = await c.get(placed);
			return {
				// Keyed by the subject itself.
				add: (subject: string, handle: string, lifetimeMs: number) =>
					sets.add(subject, handle, lifetimeMs, subject),
				members: sets.members,
				remove: sets.remove,
				erase: sets.erase,
				migrate: sets.migrate,
			};
		}),
		m.provide(closingList).by(async (c) =>
			deferredIn({
				...(await placeIn(c, closings)),
				shards: c.section["closing-shards"],
				perShard: c.section["closings-per-shard"],
			}),
		),
	],
);
