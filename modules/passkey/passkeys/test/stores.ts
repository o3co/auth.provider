import { randomBytes } from "node:crypto";
import { defineModule, Unavailable } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type ChallengeStore,
	challengeStore,
	type PasskeyKeys,
	type PasskeyRecords,
	type PasskeyStore,
	passkeyStore,
	type StoredChallenge,
	type StoredPasskey,
} from "../src/store.ts";

type Space = keyof PasskeyKeys;
type Race = (record: StoredPasskey) => StoredPasskey;
type Together = Required<Pick<PasskeyStore, "updateTogether">>;

/**
 * passkeys' stores on the records stand-in, on the given clock, each behind a switch: credentials
 * and subjects in one stand-in, apart by their keys. `together` offers the change of records of both
 * spaces as one; `loseNextTogether` lets the next such change take effect, its answer lost.
 */
export function memoryStores(
	now: () => number = () => 0,
	{ together = false }: { readonly together?: boolean } = {},
) {
	const size = { shards: 1, perShard: 1 };
	const stand = memoryRecords<StoredPasskey>(now, size);
	const at = (space: Space, key: string) => `${space}/${key}`;
	const races: Partial<Record<Space, Race>> = {};
	const keyed = (space: Space): PasskeyRecords => ({
		save: (key, record) => stand.records.create(at(space, key), record, "endless"),
		read: (key) => stand.records.read(at(space, key)),
		// A race is this space's alone, kept here and never handed to the shared stand-in: the change runs
		// on what it read, the other writer writes, and the change runs again on that. A missing record,
		// or a change that throws on what it read, leaves the race waiting for this space.
		update: async (key, change) => {
			const race = races[space];
			const read = stand.peek(at(space, key));
			if (!race || read === undefined) return stand.records.change(at(space, key), change);
			change(read);
			delete races[space];
			await stand.records.change(at(space, key), (record) => ({ value: race(record) }));
			return stand.records.change(at(space, key), change);
		},
	});
	const endless = (next: { readonly value: StoredPasskey } | undefined) =>
		next && { value: next.value, lifetimeMs: "endless" as const };
	let loseNext = false;
	const changeTogether: Together["updateTogether"] = async (keys, p) => {
		const fixed = keys.credentials.length;
		let watched: PasskeyKeys = { credentials: [], subjects: [] };
		const split = <T>(fixedOnes: readonly T[], watchedOnes: readonly T[]) => ({
			credentials: [
				...fixedOnes.slice(0, fixed),
				...watchedOnes.slice(0, watched.credentials.length),
			],
			subjects: [...fixedOnes.slice(fixed), ...watchedOnes.slice(watched.credentials.length)],
		});
		const changed = await stand.records.changeRecords(
			[
				...keys.credentials.map((key) => at("credentials", key)),
				...keys.subjects.map((key) => at("subjects", key)),
			],
			{
				watch: (read) => {
					const named = p.watch(split(read, []));
					watched = { credentials: named.credentials ?? [], subjects: named.subjects ?? [] };
					return [
						...watched.credentials.map((key) => at("credentials", key)),
						...watched.subjects.map((key) => at("subjects", key)),
					];
				},
				decide: (read, found) => {
					const next = p.change(split(read, found));
					const [ofCredentials, ofSubjects] = [next.credentials ?? [], next.subjects ?? []];
					const fixedSubjects = keys.subjects.length;
					const of = (list: typeof ofCredentials, from: number, count: number) =>
						Array.from({ length: count }, (_, n) => endless(list[from + n]));
					return {
						targets: [...of(ofCredentials, 0, fixed), ...of(ofSubjects, 0, fixedSubjects)],
						watched: [
							...of(ofCredentials, fixed, watched.credentials.length),
							...of(ofSubjects, fixedSubjects, watched.subjects.length),
						],
					};
				},
			},
		);
		if (loseNext) {
			loseNext = false;
			throw new Unavailable("passkeys");
		}
		return split(changed.targets, changed.watched);
	};
	const challengesStand = memoryRecords<StoredChallenge>(now, size);
	const down = {
		credentials: unavailableSwitch<PasskeyRecords>("credentials"),
		subjects: unavailableSwitch<PasskeyRecords>("subjects"),
		together: unavailableSwitch<Together>("passkeys"),
		challenges: unavailableSwitch<ChallengeStore>("challenges"),
	};
	const passkeys: PasskeyStore = {
		credentials: down.credentials.wrap(keyed("credentials")),
		subjects: down.subjects.wrap(keyed("subjects")),
		...(together ? down.together.wrap({ updateTogether: changeTogether }) : {}),
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
		raceSubjects: (race: Race) => {
			races.subjects = race;
		},
		raceCredentials: (race: Race) => {
			races.credentials = race;
		},
		loseNextTogether: () => {
			loseNext = true;
		},
	};
}

/** A token naming each registration's write, as passkeys makes one. */
export const writeToken = () => randomBytes(16).toString("base64url");
