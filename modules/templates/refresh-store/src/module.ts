import { type BuildContext, defineModule } from "@mod/kernel";
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
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { section } from "./section.ts";

/** Each need refresh states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof refreshStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const guarantees = Object.values(guaranteeFor);
const families: Space = { name: "refresh-store.families", guarantees };
const redemptions: Space = { name: "refresh-store.redemptions", guarantees };
const bySession: Space = { name: "refresh-store.session-families", guarantees };
const byFamily: Space = { name: "refresh-store.issued-access", guarantees };
const links: Space = { name: "refresh-store.token-families", guarantees };
const settles: Space = { name: "refresh-store.settles", guarantees };

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

// Safe on many instances given the same `settle-shards` and `settles-per-shard` on each
// (deployment-guarantees, Several instances): revocations to settle go to a shard by their hash, and a
// sweep walks only the shards it counts.
export default defineModule(
	{ name: "refresh-store", replicaSafe: true, section, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => families),
		m.contribute(spaces).by(() => redemptions),
		m.contribute(spaces).by(() => bySession),
		m.contribute(spaces).by(() => byFamily),
		m.contribute(spaces).by(() => links),
		m.contribute(spaces).by(() => settles),
		m.provide(familyStore).by(async (c) => {
			const records = recordsIn<StoredFamily>(await placeIn(c, families));
			return { save: records.create, read: records.read, update: records.change };
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
