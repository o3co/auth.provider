import { defineModule } from "@mod/kernel";
import { recordsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store } from "@mod/store";
import {
	type ChallengeStore,
	challengeStore,
	type challengeStoreNeeds,
	type PasskeyStore,
	passkeyStore,
	type passkeyStoreNeeds,
	type StoredChallenge,
	type StoredPasskey,
} from "@mod/webauthn";

/** Each need webauthn states for its passkeys, as the guarantee a space declares for it. */
const guaranteeFor: Record<keyof typeof passkeyStoreNeeds, Guarantee> = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	confirmedReads: "confirmed-reads",
};
/** Each need webauthn states for its challenges, as what meets it: a guarantee, or records under a secret. */
const { namesFromSecret: challengeRecordsFor, ...challengeGuaranteeFor } = {
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof challengeStoreNeeds, Guarantee | typeof secretRecordsIn>;
const passkeySpace = (name: string): Space => ({ name, guarantees: Object.values(guaranteeFor) });
const credentials = passkeySpace("webauthn-store.credentials");
const subjects = passkeySpace("webauthn-store.subjects");
const challenges: Space = {
	name: "webauthn-store.challenges",
	guarantees: Object.values(challengeGuaranteeFor),
};

export default defineModule({ name: "webauthn-store" }, (m) => [
	m.contribute(spaces).by(() => credentials),
	m.contribute(spaces).by(() => subjects),
	m.contribute(spaces).by(() => challenges),
	m.provide(passkeyStore).by(async (c): Promise<PasskeyStore> => {
		const place = { store: await c.get(store), log: c.log, random: c.random };
		/** One space's records, kept as long as webauthn says. */
		const passkeyRecordsIn = (space: Space) => {
			const records = recordsIn<StoredPasskey>({ ...place, space });
			return {
				save: records.create,
				read: records.read,
				update: records.change,
			};
		};
		return { credentials: passkeyRecordsIn(credentials), subjects: passkeyRecordsIn(subjects) };
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
