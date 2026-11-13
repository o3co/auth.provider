import {
	type RefreshLocks,
	refreshLocks,
	type refreshLocksNeeds,
	type StoredUpstreamTokens,
	type UpstreamTokenStore,
	upstreamTokenStore,
	type upstreamTokenStoreNeeds,
} from "@mod/federation-tokens";
import { contract, defineModule, optional, probes } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";

/** Each need federation-tokens states for its records, as the guarantee a space declares for it. */
const tokensGuaranteeFor: Record<keyof typeof upstreamTokenStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesFailover: "replicated",
};
/** Each need it states for its locks. */
const locksGuaranteeFor: Record<keyof typeof refreshLocksNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
};
/** Each session's upstream tokens, its subject's: indexed by it, erased by federation-tokens' eraser, at the tombstone's floor. */
const tokens: Space = {
	name: "federation-tokens-store.tokens",
	guarantees: [...new Set([...Object.values(tokensGuaranteeFor), ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "federation-tokens",
};
const locks: Space = {
	name: "federation-tokens-store.locks",
	guarantees: Object.values(locksGuaranteeFor),
	subjectData: "none",
};

/** The tokens' records over the phase this process reads once. */
const placed = contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredUpstreamTokens>>>>(
	"federation-tokens-store.placed",
);

export default defineModule(
	{
		name: "federation-tokens-store",
		replicaSafe: true,
		takes: [store, optional(storeControl)],
	},
	(m) => [
		m.contribute(spaces).by(() => tokens),
		m.contribute(spaces).by(() => indexSpaceOf(tokens)),
		m.contribute(spaces).by(() => locks),
		m.provide(placed).by(async (c) =>
			phasedRecordsIn<StoredUpstreamTokens>(
				{
					store: await c.get(store),
					space: tokens,
					index: indexSpaceOf(tokens),
					log: c.log,
					random: c.random,
				},
				subjectRecordsPhase.once(await c.getOptional(storeControl)),
				"federation-tokens-store",
				c.refuse,
			),
		),
		m.provide(upstreamTokenStore).by(async (c): Promise<UpstreamTokenStore> => {
			const records = await c.get(placed);
			return {
				save: records.create,
				read: records.read,
				update: records.change,
				remove: records.remove,
				scan: records.scan,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const records = await c.get(placed);
			return { name: "federation-tokens-store.phase", check: () => records.ready() };
		}),
		m.provide(refreshLocks).by(async (c): Promise<RefreshLocks> => {
			const place = { store: await c.get(store), space: locks, log: c.log, random: c.random };
			const marked = recordsIn<string>(place);
			return {
				hold: (name, mark, lifetimeMs) => marked.create(name, mark, lifetimeMs),
				update: marked.change,
			};
		}),
	],
);
