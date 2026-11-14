import { type BuildContext, contract, defineModule, optional, probes } from "@mod/kernel";
import { deferredIn, keyedSetsIn } from "@mod/records";
import {
	noticeBodies,
	type noticeBodiesNeeds,
	noticeQueue,
	type noticeQueueNeeds,
	pendingNotices,
	type pendingNoticesNeeds,
	sessionClients,
	type sessionClientsNeeds,
} from "@mod/rp-logout";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
import { section } from "./section.ts";

/** Each need rp-logout states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof sessionClientsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const held: Space = {
	name: "rp-logout-store.clients",
	guarantees: Object.values(guaranteeFor),
	subjectData: "none",
};
/** The notices state the same needs; typed by their own, so a need they add alone fails the type check. */
const noticeGuaranteeFor: Record<keyof typeof pendingNoticesNeeds, Guarantee> = guaranteeFor;
const pending: Space = {
	name: "rp-logout-store.notices",
	guarantees: Object.values(noticeGuaranteeFor),
};
/** The bodies state the same needs, typed by their own. */
const bodyGuaranteeFor: Record<keyof typeof noticeBodiesNeeds, Guarantee> = guaranteeFor;
/** Each notice's body, by its id (a digest): a subject's, kept indexed by it, erased by rp-logout, at the tombstone's floor. */
const bodies: Space = {
	name: "rp-logout-store.notice-bodies",
	guarantees: [...new Set([...Object.values(bodyGuaranteeFor), ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "rp-logout",
};
/** The entries to try, each a body's id and a time: no subject's data. */
const queueGuaranteeFor: Record<keyof typeof noticeQueueNeeds, Guarantee> = guaranteeFor;
const queue: Space = {
	name: "rp-logout-store.deferred",
	guarantees: Object.values(queueGuaranteeFor),
	subjectData: "none",
};

/** The bodies' records over the phase this process reads once. */
const placed =
	contract<Awaited<ReturnType<typeof phasedRecordsIn<string>>>>("rp-logout-store.placed");

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

// Safe on many instances given the same `notice-shards` and `notices-per-shard` on each
// (deployment-guarantees, Several instances): logout notices go to a shard by their hash, and a sweep
// walks only the shards it counts.
export default defineModule(
	{
		name: "rp-logout-store",
		replicaSafe: true,
		section,
		takes: [store, optional(storeControl)],
	},
	(m) => [
		m.contribute(spaces).by(() => held),
		m.contribute(spaces).by(() => pending),
		m.contribute(spaces).by(() => bodies),
		m.contribute(spaces).by(() => indexSpaceOf(bodies)),
		m.contribute(spaces).by(() => queue),
		m
			.provide(placed)
			.by(async (c) =>
				phasedRecordsIn<string>(
					{ ...(await placeIn(c, bodies)), index: indexSpaceOf(bodies) },
					subjectRecordsPhase.once(await c.getOptional(storeControl)),
					"rp-logout-store",
					c.refuse,
				),
			),
		// The builder's own ports, a body created for its subject and never changed.
		m.provide(noticeBodies).by(async (c) => {
			const builder = await c.get(placed);
			return {
				create: builder.create,
				read: builder.read,
				remove: builder.remove,
				erase: builder.erase,
				migrate: builder.migrate,
			};
		}),
		m.provide(noticeQueue).by(async (c) =>
			deferredIn({
				...(await placeIn(c, queue)),
				shards: c.section["notice-shards"],
				perShard: c.section["notices-per-shard"],
			}),
		),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const builder = await c.get(placed);
			return { name: "rp-logout-store.phase", check: () => builder.ready() };
		}),
		m.provide(sessionClients).by(async (c) =>
			keyedSetsIn({
				...(await placeIn(c, held)),
				cap: c.section["clients-per-session"],
				clock: c.clock,
			}),
		),
		m.provide(pendingNotices).by(async (c) =>
			deferredIn({
				...(await placeIn(c, pending)),
				shards: c.section["notice-shards"],
				perShard: c.section["notices-per-shard"],
			}),
		),
	],
);
