import { defineModule } from "@mod/kernel";
import {
	type ChallengeStore as KeptChallenges,
	type PasskeyStore as KeptPasskeys,
	type challengeStoreNeeds as keptChallengeNeeds,
	type passkeyStoreNeeds as keptPasskeyNeeds,
	challengeStore as passkeysChallengeStore,
	passkeyStore as passkeysPasskeyStore,
} from "@mod/passkeys";
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
// passkeys states the same needs: the same spaces meet them.
guaranteeFor satisfies Record<keyof typeof keptPasskeyNeeds, Guarantee>;
challengeGuaranteeFor satisfies Record<
	Exclude<keyof typeof keptChallengeNeeds, "namesFromSecret">,
	Guarantee
>;
const passkeySpace = (name: string): Space => ({ name, guarantees: Object.values(guaranteeFor) });
const credentials = passkeySpace("webauthn-store.credentials");
const subjects = passkeySpace("webauthn-store.subjects");
const challenges: Space = {
	name: "webauthn-store.challenges",
	guarantees: Object.values(challengeGuaranteeFor),
};

type Place = Parameters<typeof recordsIn>[0];

/** One space's records, kept as long as the keeper says. */
const passkeyRecordsIn = (place: Omit<Place, "space">, space: Space) => {
	const records = recordsIn<StoredPasskey>({ ...place, space });
	return { save: records.create, read: records.read, update: records.change };
};
const challengeRecordsIn = (place: Omit<Place, "space">) => {
	const records = challengeRecordsFor<StoredChallenge>({ ...place, space: challenges });
	return {
		open: records.create,
		take: (challenge: string, mark: StoredChallenge) =>
			records.change(challenge, () => ({ value: mark })),
	};
};

export default defineModule({ name: "webauthn-store" }, (m) => [
	m.contribute(spaces).by(() => credentials),
	m.contribute(spaces).by(() => subjects),
	m.contribute(spaces).by(() => challenges),
	m.provide(passkeyStore).by(async (c): Promise<PasskeyStore> => {
		const place = { store: await c.get(store), log: c.log, random: c.random };
		return {
			credentials: passkeyRecordsIn(place, credentials),
			subjects: passkeyRecordsIn(place, subjects),
		};
	}),
	m.provide(challengeStore).by(async (c): Promise<ChallengeStore> => {
		const place = { store: await c.get(store), log: c.log, random: c.random };
		return challengeRecordsIn(place);
	}),
	// The same records, through the interfaces passkeys states: its records are webauthn's, kept as they were.
	m.provide(passkeysPasskeyStore).by(async (c): Promise<KeptPasskeys> => {
		const place = { store: await c.get(store), log: c.log, random: c.random };
		return {
			credentials: passkeyRecordsIn(place, credentials),
			subjects: passkeyRecordsIn(place, subjects),
		} as unknown as KeptPasskeys;
	}),
	m.provide(passkeysChallengeStore).by(async (c): Promise<KeptChallenges> => {
		const place = { store: await c.get(store), log: c.log, random: c.random };
		return challengeRecordsIn(place) as unknown as KeptChallenges;
	}),
]);
