import {
	type RefreshLocks,
	refreshLocks,
	type refreshLocksNeeds,
	type StoredUpstreamTokens,
	type UpstreamTokenStore,
	upstreamTokenStore,
	type upstreamTokenStoreNeeds,
} from "@mod/federation-tokens";
import { defineModule } from "@mod/kernel";
import { recordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need federation-tokens states for its records, as the guarantee a space declares for it. */
const tokensGuaranteeFor: Record<keyof typeof upstreamTokenStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesFailover: "replicated",
};
/** Each need it states for its locks. */
const locksGuaranteeFor: Record<keyof typeof refreshLocksNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
};
const tokens: Space = {
	name: "federation-tokens-store.tokens",
	guarantees: Object.values(tokensGuaranteeFor),
};
const locks: Space = {
	name: "federation-tokens-store.locks",
	guarantees: Object.values(locksGuaranteeFor),
};

export default defineModule({ name: "federation-tokens-store", takes: [store] }, (m) => [
	m.contribute(spaces).by(() => tokens),
	m.contribute(spaces).by(() => locks),
	m.provide(upstreamTokenStore).by(async (c): Promise<UpstreamTokenStore> => {
		const place = { store: await c.get(store), space: tokens, log: c.log, random: c.random };
		const records = recordsIn<StoredUpstreamTokens>(place);
		return {
			save: records.create,
			read: records.read,
			update: records.change,
			remove: records.remove,
			scan: records.scan,
		};
	}),
	m.provide(refreshLocks).by(async (c): Promise<RefreshLocks> => {
		const place = { store: await c.get(store), space: locks, log: c.log, random: c.random };
		const marked = recordsIn<string>(place);
		return {
			hold: (name, mark, lifetimeMs) => marked.create(name, mark, lifetimeMs),
			update: marked.change,
		};
	}),
]);
