import { contract, defineModule, optional, probes } from "@mod/kernel";
import {
	type ChallengeStore,
	challengeStore,
	type challengeStoreNeeds,
	type PasskeyStore,
	passkeyStore,
	type passkeyStoreNeeds,
	type RegistrationChallengeStore,
	registrationChallengeStore,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/passkeys";
import { secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedJointRecordsIn,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";
import { challengeLifetimeMaxMs } from "@mod/webauthn";

/** Each need passkeys states for its passkeys, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof passkeyStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
/**
 * The needs a feature states as `true`, each met by what a space declares; a need of another value,
 * such as a bound, is no guarantee, and is read where the space states it.
 */
export type StatedNeeds<N> = { readonly [K in keyof N]: N[K] extends true ? K : never }[keyof N];
/** Each need passkeys states for its challenges, as the guarantee a space declares for it, or records under a secret. */
const { namesFromSecret: challengesUnder, ...challengeGuaranteeFor } = {
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: { secret: true } as const,
} satisfies Record<StatedNeeds<typeof challengeStoreNeeds>, Guarantee | { readonly secret: true }>;
/** A space of a subject's passkeys or holder: kept indexed by it, erased by passkeys, at the tombstone's floor. */
const passkeySpace = (name: string): Space => ({
	name,
	guarantees: [...new Set([...Object.values(guaranteeFor), ...tombstoneFloor])],
	subjectData: "online-indexed",
	erasedBy: "passkeys",
});
// The names webauthn's records were kept under, so the passkeys kept before read as they were.
const credentials = passkeySpace("webauthn-store.credentials");
const subjects = passkeySpace("webauthn-store.subjects");
/**
 * Assertion challenges: who asked, by its own name, a digest of its id and a time; no subject's
 * data. A node before 0.20 also keeps a subject's registration challenges here, each ending at
 * webauthn's `challengeLifetimeMaxMs`: account erasure is enabled only once that long has passed
 * in its maintenance window.
 */
const challenges: Space = {
	name: "webauthn-store.challenges",
	guarantees: Object.values(challengeGuaranteeFor),
	subjectData: "none",
};
/** Registration challenges, each a subject's for at most webauthn's ceiling: fenced by its tombstone, ending by then. */
const registrations: Space = {
	name: "webauthn-store.registration-challenges",
	guarantees: [...new Set([...Object.values(challengeGuaranteeFor), ...tombstoneFloor])],
	subjectData: "bounded",
	boundedMs: challengeLifetimeMaxMs,
	erasedBy: "passkeys",
};

/** The passkey spaces' records, their change as one, and the registration challenges', over the one phase this process reads once. */
const placed = contract<{
	readonly credentials: Awaited<ReturnType<typeof phasedRecordsIn<StoredPasskey>>>;
	readonly subjects: Awaited<ReturnType<typeof phasedRecordsIn<StoredPasskey>>>;
	readonly joint: Awaited<
		ReturnType<typeof phasedJointRecordsIn<"credentials" | "subjects", StoredPasskey>>
	>;
	readonly registrations: Awaited<ReturnType<typeof phasedRecordsIn<StoredChallenge>>>;
}>("webauthn-store.placed");

/** passkeys' store interface over a space's records: the builder's own ports. */
const portsOf = (records: Awaited<ReturnType<typeof phasedRecordsIn<StoredPasskey>>>) => ({
	save: records.create,
	read: records.read,
	update: records.change,
	erase: records.erase,
	migrate: records.migrate,
});

export default defineModule(
	{ name: "webauthn-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => credentials),
		m.contribute(spaces).by(() => indexSpaceOf(credentials)),
		m.contribute(spaces).by(() => subjects),
		m.contribute(spaces).by(() => indexSpaceOf(subjects)),
		m.contribute(spaces).by(() => challenges),
		m.contribute(spaces).by(() => registrations),
		m.contribute(spaces).by(() => indexSpaceOf(registrations)),
		m.provide(placed).by(async (c) => {
			const phase = subjectRecordsPhase.once(await c.getOptional(storeControl));
			const at = async (space: Space) => ({
				store: await c.get(store),
				space,
				index: indexSpaceOf(space),
				log: c.log,
				random: c.random,
			});
			const [credentialsAt, subjectsAt] = [await at(credentials), await at(subjects)];
			return {
				credentials: await phasedRecordsIn<StoredPasskey>(
					credentialsAt,
					phase,
					"webauthn-store",
					c.refuse,
				),
				subjects: await phasedRecordsIn<StoredPasskey>(
					subjectsAt,
					phase,
					"webauthn-store",
					c.refuse,
				),
				// A store that cannot write records of two partitions as one refuses the boot, told by subject-records.
				joint: await phasedJointRecordsIn<"credentials" | "subjects", StoredPasskey>(
					{ credentials: credentialsAt, subjects: subjectsAt },
					phase,
					"webauthn-store",
					c.refuse,
				),
				registrations: await phasedRecordsIn<StoredChallenge>(
					await at(registrations),
					phase,
					"webauthn-store",
					c.refuse,
					challengesUnder,
				),
			};
		}),
		m.provide(passkeyStore).by(async (c): Promise<PasskeyStore> => {
			const { credentials: c1, subjects: s1, joint } = await c.get(placed);
			return {
				credentials: portsOf(c1),
				subjects: portsOf(s1),
				updateAsOne: joint.changeSubjectRecords,
			};
		}),
		m.provide(registrationChallengeStore).by(async (c): Promise<RegistrationChallengeStore> => {
			const { registrations: r } = await c.get(placed);
			return {
				open: r.create,
				update: r.change,
				erase: r.erase,
				migrate: r.migrate,
			};
		}),
		m.provide(challengeStore).by(async (c): Promise<ChallengeStore> => {
			const place = { store: await c.get(store), space: challenges, log: c.log, random: c.random };
			const records = secretRecordsIn<StoredChallenge>(place);
			return {
				open: records.create,
				take: (challenge, mark) => records.change(challenge, () => ({ value: mark })),
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const { credentials: c1, subjects: s1, joint, registrations: r } = await c.get(placed);
			return {
				name: "webauthn-store.phase",
				check: async () => {
					await c1.ready();
					await s1.ready();
					await joint.ready();
					await r.ready();
				},
			};
		}),
	],
);
