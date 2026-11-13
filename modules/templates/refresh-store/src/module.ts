import { type BuildContext, contract, defineModule, optional, probes } from "@mod/kernel";
import { deferredIn, keyedSetsIn, recordsIn } from "@mod/records";
import {
	familyStore,
	issuedAccess,
	redemptionStore,
	type refreshStoreNeeds,
	type StoredFamily,
	type StoredLink,
	type StoredRedemption,
	sessionFamilies,
	settleList,
	tokenFamilies,
} from "@mod/refresh";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
import { section } from "./section.ts";

/** Each need refresh states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof refreshStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const guarantees = Object.values(guaranteeFor);
/** Families, each a subject's: kept indexed by it, erased by refresh's eraser, at the tombstone's floor. */
const families: Space = {
	name: "refresh-store.families",
	guarantees: [...new Set([...guarantees, ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "refresh",
};
/** What each redemption left (a family's name, or that none may start), by the redemption's name: no subject. */
const redemptions: Space = { name: "refresh-store.redemptions", guarantees, subjectData: "none" };
/** Each access token's family's name, by the token's id: no subject. */
const links: Space = { name: "refresh-store.token-families", guarantees, subjectData: "none" };
// Deprecated, neither read nor written by refresh: ids of sessions, families and tokens, no subject.
const bySession: Space = {
	name: "refresh-store.session-families",
	guarantees,
	subjectData: "none",
};
const byFamily: Space = { name: "refresh-store.issued-access", guarantees, subjectData: "none" };
const settles: Space = { name: "refresh-store.settles", guarantees, subjectData: "none" };

/** The families' records over the phase this process reads once. */
const placed =
	contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredFamily>>>>("refresh-store.placed");

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

// Safe on many instances: each record is in the shared store; the settle list's shards, deprecated, are
// read by no one.
export default defineModule(
	{ name: "refresh-store", replicaSafe: true, section, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => families),
		m.contribute(spaces).by(() => indexSpaceOf(families)),
		m.contribute(spaces).by(() => redemptions),
		m.contribute(spaces).by(() => bySession),
		m.contribute(spaces).by(() => byFamily),
		m.contribute(spaces).by(() => links),
		m.contribute(spaces).by(() => settles),
		m
			.provide(placed)
			.by(async (c) =>
				phasedRecordsIn<StoredFamily>(
					{ ...(await placeIn(c, families)), index: indexSpaceOf(families) },
					subjectRecordsPhase.once(await c.getOptional(storeControl)),
					"refresh-store",
					c.refuse,
				),
			),
		m.provide(familyStore).by(async (c) => {
			const records = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				erase: records.erase,
				migrate: records.migrate,
				unowned: records.unowned,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const records = await c.get(placed);
			return { name: "refresh-store.phase", check: () => records.ready() };
		}),
		m.provide(redemptionStore).by(async (c) => {
			const records = recordsIn<StoredRedemption>(await placeIn(c, redemptions));
			return { save: records.create, read: records.read };
		}),
		m.provide(tokenFamilies).by(async (c) => {
			const records = recordsIn<StoredLink>(await placeIn(c, links));
			return { save: records.create, read: records.read };
		}),
		m.provide(sessionFamilies).by(async (c) =>
			keyedSetsIn({
				...(await placeIn(c, bySession)),
				cap: c.section["families-per-session"],
				clock: c.clock,
			}),
		),
		m.provide(issuedAccess).by(async (c) =>
			keyedSetsIn({
				...(await placeIn(c, byFamily)),
				cap: c.section["tokens-per-family"],
				clock: c.clock,
			}),
		),
		m.provide(settleList).by(async (c) =>
			deferredIn({
				...(await placeIn(c, settles)),
				shards: c.section["settle-shards"],
				perShard: c.section["settles-per-shard"],
			}),
		),
	],
);
