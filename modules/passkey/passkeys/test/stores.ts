import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type ChallengeStore,
	challengeStore,
	type PasskeyRecords,
	type PasskeyStore,
	passkeyStore,
	type StoredChallenge,
	type StoredPasskey,
} from "../src/store.ts";

/** passkeys' stores on the records stand-in, on the given clock, each behind a switch. */
export function memoryStores(now: () => number = () => 0) {
	const size = { shards: 1, perShard: 1 };
	const keyed = () => {
		const stand = memoryRecords<StoredPasskey>(now, size);
		const records: PasskeyRecords = {
			save: (key, record) => stand.records.create(key, record, "endless"),
			read: stand.records.read,
			update: stand.records.change,
		};
		return { stand, records };
	};
	const [credentials, subjects] = [keyed(), keyed()];
	const challengesStand = memoryRecords<StoredChallenge>(now, size);
	const down = {
		credentials: unavailableSwitch<PasskeyRecords>("credentials"),
		subjects: unavailableSwitch<PasskeyRecords>("subjects"),
		challenges: unavailableSwitch<ChallengeStore>("challenges"),
	};
	const passkeys: PasskeyStore = {
		credentials: down.credentials.wrap(credentials.records),
		subjects: down.subjects.wrap(subjects.records),
	};
	const challenges = down.challenges.wrap({
		open: challengesStand.records.create,
		take: (challenge, mark) => challengesStand.records.change(challenge, () => ({ value: mark })),
	});
	const module = defineModule({ name: "webauthn-stores" }, (m) => [
		m.provide(passkeyStore).by(() => passkeys),
		m.provide(challengeStore).by(() => challenges),
	]);
	return {
		module,
		passkeys,
		challenges,
		down,
		raceSubjects: subjects.stand.raceNextChange,
		raceCredentials: credentials.stand.raceNextChange,
	};
}
