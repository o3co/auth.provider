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
import { type BuildContext, contract, defineModule, optional, probes } from "@mod/kernel";
import { recordsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedKeyedSetsIn,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
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
/** Each a subject's: grants, pending pairs and listings indexed by it, erased by federation-grants, at the tombstone's floor. */
const ofSubjects = (guarantees: readonly Guarantee[]) => ({
	guarantees: [...new Set([...guarantees, ...tombstoneFloor])],
	erasedBy: "federation-grants",
});
const grants: Space = {
	name: "federation-grants-store.grants",
	...ofSubjects(Object.values(grantsGuaranteeFor)),
	subjectData: "online-indexed",
};
const steps: Space = {
	name: "federation-grants-store.steps",
	guarantees: Object.values(stepsGuaranteeFor),
	subjectData: "none",
};
/** Pending pairs, keyed by client and subject, so indexed; the floor adds durable and replicated to their no eviction. */
const pending: Space = {
	name: "federation-grants-store.pending",
	...ofSubjects(Object.values(pendingGuaranteeFor)),
	subjectData: "online-indexed",
};
/** Each subject's listing, keyed by the subject itself. */
const listed: Space = {
	name: "federation-grants-store.subjects",
	...ofSubjects(Object.values(listedGuaranteeFor)),
	subjectData: "online-keyed",
};
const locks: Space = {
	name: "federation-grants-store.locks",
	guarantees: Object.values(locksGuaranteeFor),
	subjectData: "none",
};

/** A space's place: the composition's store, with its log and randomness. */
const placeIn = async (c: Pick<BuildContext<unknown>, "get" | "log" | "random">, space: Space) => ({
	store: await c.get(store),
	space,
	log: c.log,
	random: c.random,
});

/** The phase, read once for the three builders over it. */
const phase = contract<ReturnType<typeof subjectRecordsPhase.once>>(
	"federation-grants-store.phase",
);
/** Each builder over the phase, built once, so the probe and the stores share it. */
const placed = contract<{
	readonly grants: Awaited<ReturnType<typeof phasedRecordsIn<StoredGrant>>>;
	readonly pending: Awaited<ReturnType<typeof phasedKeyedSetsIn>>;
	readonly listed: Awaited<ReturnType<typeof phasedKeyedSetsIn>>;
}>("federation-grants-store.placed");

export default defineModule(
	// Safe on many instances: a record's expiry is set by the writing instance's clock, kept in step with the
	// others' by the operator (deployment-guarantees, Several instances).
	{
		name: "federation-grants-store",
		replicaSafe: true,
		section,
		takes: [store, optional(storeControl)],
	},
	(m) => [
		m.contribute(spaces).by(() => grants),
		m.contribute(spaces).by(() => indexSpaceOf(grants)),
		m.contribute(spaces).by(() => steps),
		m.contribute(spaces).by(() => pending),
		m.contribute(spaces).by(() => indexSpaceOf(pending)),
		m.contribute(spaces).by(() => listed),
		m.contribute(spaces).by(() => indexSpaceOf(listed)),
		m.contribute(spaces).by(() => locks),
		m.provide(phase).by(async (c) => subjectRecordsPhase.once(await c.getOptional(storeControl))),
		m.provide(placed).by(async (c) => {
			const read = await c.get(phase);
			const where = "federation-grants-store";
			const setsIn = async (space: Space, cap: number) =>
				phasedKeyedSetsIn(
					{ ...(await placeIn(c, space)), index: indexSpaceOf(space), cap, clock: c.clock },
					read,
					where,
					c.refuse,
				);
			return {
				grants: await phasedRecordsIn<StoredGrant>(
					{ ...(await placeIn(c, grants)), index: indexSpaceOf(grants) },
					read,
					where,
					c.refuse,
				),
				pending: await setsIn(pending, c.section["pending-per-client-and-subject"]),
				listed: await setsIn(listed, c.section["grants-per-subject"]),
			};
		}),
		m.provide(grantStore).by(async (c): Promise<GrantStore> => {
			const { grants: records } = await c.get(placed);
			return {
				create: records.create,
				read: records.read,
				change: records.change,
				scan: records.scan,
				erase: records.erase,
				migrate: records.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const built = await c.get(placed);
			const check = async () => {
				await built.grants.ready();
				await built.pending.ready();
				await built.listed.ready();
			};
			return { name: "federation-grants-store.phase", check };
		}),
		m.provide(stepStore).by(async (c): Promise<StepStore> => {
			const records = stepRecordsFor<StoredStep>(await placeIn(c, steps));
			return { create: records.create, read: records.read, change: records.change };
		}),
		m.provide(pendingIntents).by(async (c): Promise<PendingIntents> => {
			const { pending: sets } = await c.get(placed);
			return { add: sets.add, remove: sets.remove, erase: sets.erase, migrate: sets.migrate };
		}),
		m.provide(subjectGrants).by(async (c): Promise<SubjectGrants> => {
			const { listed: sets } = await c.get(placed);
			return {
				// A listing is keyed by its subject itself.
				add: (subject, grant, lifetimeMs) => sets.add(subject, grant, lifetimeMs, subject),
				members: sets.members,
				remove: sets.remove,
				erase: sets.erase,
				migrate: sets.migrate,
			};
		}),
		m.provide(refreshLockStore).by(async (c): Promise<RefreshLockStore> => {
			const records = recordsIn<string>(await placeIn(c, locks));
			return { hold: records.create, update: records.change };
		}),
	],
);
