import { type BuildContext, defineModule } from "@mod/kernel";
import { deferredIn, keyedSetsIn } from "@mod/records";
import {
	pendingNotices,
	type pendingNoticesNeeds,
	sessionClients,
	type sessionClientsNeeds,
} from "@mod/rp-logout";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { section } from "./section.ts";

/** Each need rp-logout states, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof sessionClientsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const held: Space = { name: "rp-logout-store.clients", guarantees: Object.values(guaranteeFor) };
/** The notices state the same needs; typed by their own, so a need they add alone fails the type check. */
const noticeGuaranteeFor: Record<keyof typeof pendingNoticesNeeds, Guarantee> = guaranteeFor;
const pending: Space = {
	name: "rp-logout-store.notices",
	guarantees: Object.values(noticeGuaranteeFor),
};

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

export default defineModule(
	{ name: "rp-logout-store", replicaSafe: true, section, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => held),
		m.contribute(spaces).by(() => pending),
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
