import { defineModule } from "@mod/kernel";
import {
	type ChallengeStore,
	challengeStore,
	type challengeStoreNeeds,
	type PasskeyStore,
	passkeyStore,
	type passkeyStoreNeeds,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/passkeys";
import { pairedRecordsAcross, recordsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";

/** Each need passkeys states for its passkeys, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof passkeyStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
/** Each need passkeys states for its challenges, as what meets it: a guarantee, or records under a secret. */
const { namesFromSecret: challengeRecordsFor, ...challengeGuaranteeFor } = {
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof challengeStoreNeeds, Guarantee | typeof secretRecordsIn>;
const passkeySpace = (name: string): Space => ({ name, guarantees: Object.values(guaranteeFor) });
// The names webauthn's records were kept under, so the passkeys kept before read as they were.
const credentials = passkeySpace("webauthn-store.credentials");
const subjects = passkeySpace("webauthn-store.subjects");
const challenges: Space = {
	name: "webauthn-store.challenges",
	guarantees: Object.values(challengeGuaranteeFor),
};

export default defineModule({ name: "webauthn-store", takes: [store] }, (m) => [
	m.contribute(spaces).by(() => credentials),
	m.contribute(spaces).by(() => subjects),
	m.contribute(spaces).by(() => challenges),
	m.provide(passkeyStore).by(async (c): Promise<PasskeyStore> => {
		const place = { store: await c.get(store), log: c.log, random: c.random };
		/** One space's records, kept as long as passkeys says. */
		const passkeyRecordsIn = (space: Space) => {
			const records = recordsIn<StoredPasskey>({ ...place, space });
			return {
				save: records.create,
				read: records.read,
				update: records.change,
			};
		};
		// Refused while it is built where the store writes no records of two partitions as one.
		const paired = pairedRecordsAcross<StoredPasskey, StoredPasskey>(
			{ ...place, space: credentials },
			{ ...place, space: subjects },
			"webauthn-store",
			(where, reason) => c.refuse(where, reason),
		);
		return {
			credentials: passkeyRecordsIn(credentials),
			subjects: passkeyRecordsIn(subjects),
			updateTogether: async (keys, p) => {
				const changed = await paired.changeRecords(
					{ first: keys.credentials, second: keys.subjects },
					{
						watch: (read) => {
							const named = p.watch({ credentials: read.first, subjects: read.second });
							return { first: named.credentials, second: named.subjects };
						},
						decide: (read) => {
							const next = p.change({ credentials: read.first, subjects: read.second });
							return { first: next.credentials, second: next.subjects };
						},
					},
				);
				return { credentials: changed.first, subjects: changed.second };
			},
		};
	}),
	m.provide(challengeStore).by(async (c): Promise<ChallengeStore> => {
		const place = { store: await c.get(store), space: challenges, log: c.log, random: c.random };
		const records = challengeRecordsFor<StoredChallenge>(place);
		return {
			open: records.create,
			take: (challenge, mark) => records.change(challenge, () => ({ value: mark })),
		};
	}),
]);
