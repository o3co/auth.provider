import { type BuildContext, defineModule } from "@mod/kernel";
import { deferredIn, keyedSetsIn, recordsIn } from "@mod/records";
import {
	issuedTokens,
	type issuedTokensNeeds,
	pendingSessions,
	type pendingSessionsNeeds,
	tokenIndex,
	type tokenIndexNeeds,
} from "@mod/session-tokens";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { section } from "./section.ts";

/** Each need session-tokens states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof issuedTokensNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const issued: Space = {
	name: "session-tokens-store.issued",
	guarantees: Object.values(guaranteeFor),
};
const indexGuaranteeFor: Record<keyof typeof tokenIndexNeeds, Guarantee> = guaranteeFor;
const indexed: Space = {
	name: "session-tokens-store.index",
	guarantees: Object.values(indexGuaranteeFor),
};

const pendingGuaranteeFor: Record<keyof typeof pendingSessionsNeeds, Guarantee> = guaranteeFor;
const pending: Space = {
	name: "session-tokens-store.pending-sessions",
	guarantees: Object.values(pendingGuaranteeFor),
};

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

// Safe on many instances given the same `pending-shards` and `pending-per-shard` on each
// (deployment-guarantees, Several instances): pushed-out tokens go to a shard by their hash, and a
// sweep walks only the shards it counts.
export default defineModule(
	{ name: "session-tokens-store", replicaSafe: true, section, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => issued),
		m.contribute(spaces).by(() => indexed),
		m.contribute(spaces).by(() => pending),
		m.provide(issuedTokens).by(async (c) => {
			const cap = c.section["references-per-session"];
			const sets = keyedSetsIn({
				...(await placeIn(c, issued)),
				cap,
				clock: c.clock,
			});
			return { ...sets, size: cap };
		}),
		m.provide(tokenIndex).by(async (c) => {
			const records = recordsIn<string>(await placeIn(c, indexed));
			return { save: records.create, read: records.read };
		}),
		m.provide(pendingSessions).by(async (c) =>
			deferredIn({
				...(await placeIn(c, pending)),
				shards: c.section["pending-shards"],
				perShard: c.section["pending-per-shard"],
			}),
		),
	],
);
