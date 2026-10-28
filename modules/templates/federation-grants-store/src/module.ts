import {
	type GrantStore,
	grantStore,
	type grantStoreNeeds,
	type PendingIntents,
	pendingIntents,
	type pendingIntentsNeeds,
	type RefreshLockStore,
	refreshLockStore,
	type refreshLockStoreNeeds,
	type StepStore,
	type StoredGrant,
	type StoredStep,
	type SubjectGrants,
	stepStore,
	type stepStoreNeeds,
	subjectGrants,
	type subjectGrantsNeeds,
} from "@mod/federation-grants";
import { type BuildContext, defineModule } from "@mod/kernel";
import { keyedSetsIn, recordsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import { section } from "./section.ts";

/** Each need federation-grants states for its grants, as the guarantee a space declares for it. */
const grantsGuaranteeFor: Record<keyof typeof grantStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	readsConfirmed: "confirmed-reads",
};
/** Each need it states for its steps, as what meets it: a guarantee, or records under a secret. */
const { namesFromSecret: stepRecordsFor, ...stepsGuaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof stepStoreNeeds, Guarantee | typeof secretRecordsIn>;
const pendingGuaranteeFor: Record<keyof typeof pendingIntentsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
};
const listedGuaranteeFor: Record<keyof typeof subjectGrantsNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
};
const locksGuaranteeFor: Record<keyof typeof refreshLockStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
};
const grants: Space = {
	name: "federation-grants-store.grants",
	guarantees: Object.values(grantsGuaranteeFor),
};
const steps: Space = {
	name: "federation-grants-store.steps",
	guarantees: Object.values(stepsGuaranteeFor),
};
const pending: Space = {
	name: "federation-grants-store.pending",
	guarantees: Object.values(pendingGuaranteeFor),
};
const listed: Space = {
	name: "federation-grants-store.subjects",
	guarantees: Object.values(listedGuaranteeFor),
};
const locks: Space = {
	name: "federation-grants-store.locks",
	guarantees: Object.values(locksGuaranteeFor),
};

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

export default defineModule(
	// Safe on many instances: a record's expiry is set by the writing instance's clock, kept in step with the
	// others' by the operator (deployment-guarantees, Several instances).
	{ name: "federation-grants-store", replicaSafe: true, section, takes: [store] },
	(m) => [
		m.contribute(spaces).by(() => grants),
		m.contribute(spaces).by(() => steps),
		m.contribute(spaces).by(() => pending),
		m.contribute(spaces).by(() => listed),
		m.contribute(spaces).by(() => locks),
		m.provide(grantStore).by(async (c): Promise<GrantStore> => {
			const records = recordsIn<StoredGrant>(await placeIn(c, grants));
			return {
				create: records.create,
				read: records.read,
				change: records.change,
				scan: records.scan,
			};
		}),
		m.provide(stepStore).by(async (c): Promise<StepStore> => {
			const records = stepRecordsFor<StoredStep>(await placeIn(c, steps));
			return { create: records.create, read: records.read, change: records.change };
		}),
		m.provide(pendingIntents).by(async (c): Promise<PendingIntents> => {
			const sets = keyedSetsIn({
				...(await placeIn(c, pending)),
				cap: c.section["pending-per-client-and-subject"],
				clock: c.clock,
			});
			return { add: sets.add, remove: sets.remove };
		}),
		m.provide(subjectGrants).by(async (c): Promise<SubjectGrants> => {
			const sets = keyedSetsIn({
				...(await placeIn(c, listed)),
				cap: c.section["grants-per-subject"],
				clock: c.clock,
			});
			return { add: sets.add, members: sets.members, remove: sets.remove };
		}),
		m.provide(refreshLockStore).by(async (c): Promise<RefreshLockStore> => {
			const records = recordsIn<string>(await placeIn(c, locks));
			return { hold: records.create, update: records.change };
		}),
	],
);
