import { createHash, randomBytes } from "node:crypto";
import { defineModule, Unavailable } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import type { Credential } from "@mod/webauthn";
import { keptPasskeys } from "../src/records.ts";
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
 * and subjects in one stand-in, apart by their keys, changed one at a time or both spaces as one;
 * `loseNextTogether` lets the next change of both take effect, its answer lost.
 */
export function memoryStores(now: () => number = () => 0) {
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
	let raceTogether: (() => Promise<void>) | undefined;
	const changeTogether: Together["updateTogether"] = async (keys, p) => {
		const fixed = keys.credentials.length;
		// A race lands once the change has read and decided: the change decides again on what is there
		// then, as records' change of records as one does when its write loses.
		const race = raceTogether;
		raceTogether = undefined;
		if (race) {
			const read = (space: Space, list: readonly string[]) =>
				list.map((key) => stand.peek(at(space, key)));
			const first = {
				credentials: read("credentials", keys.credentials),
				subjects: read("subjects", keys.subjects),
			};
			const named = p.watch(first);
			p.change({
				credentials: [...first.credentials, ...read("credentials", named.credentials ?? [])],
				subjects: [...first.subjects, ...read("subjects", named.subjects ?? [])],
			});
			await race();
		}
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
		...down.together.wrap({ updateTogether: changeTogether }),
	};
	const challenges = down.challenges.wrap({
		open: challengesStand.records.create,
		take: (challenge, mark) => challengesStand.records.change(challenge, () => ({ value: mark })),
	});
	const module = defineModule({ name: "webauthn-stores", replicaSafe: false, takes: [] }, (m) => [
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
		/** The next change of both spaces takes effect and its reply is lost, its resend too. */
		loseNextTogether: () => {
			loseNext = true;
		},
		/** Another writer runs `run` once the next change of both spaces has read and decided; it decides again. */
		raceNextTogether: (run: () => Promise<void>) => {
			raceTogether = run;
		},
		/** The store forgets the subject's holder, or the id's record, as one that lost what it was given. */
		lose: {
			holder: (subject: string) => stand.records.remove(at("subjects", keys.subject(subject))),
			record: (id: string) => stand.records.remove(at("credentials", keys.credential(id))),
		},
		/** The subject's holder as kept now, raw. */
		holderCopy: (subject: string) => stand.peek(at("subjects", keys.subject(subject))),
		/** Puts `record` in the place of the subject's holder, as a store gone back to an old copy. */
		backTo: async (subject: string, record: object) => {
			const key = at("subjects", keys.subject(subject));
			await stand.records.remove(key);
			await stand.records.create(key, stored(record), "endless");
		},
	};
}

/** A token naming each registration's write, as passkeys makes one. */
export const writeToken = () => randomBytes(16).toString("base64url");

const freshKey = () => randomBytes(32).toString("base64url");
const hashOf = (value: string) => createHash("sha256").update(value).digest("base64url");
const keys = {
	credential: (id: string) => `c-${hashOf(id)}`,
	subject: (s: string) => `s-${hashOf(s)}`,
};
const stored = (value: object) => value as unknown as StoredPasskey;
/** A live passkey's record as 0.18 wrote it: no time, no removal. */
const live18 = (subject: string) =>
	stored({ v: 1, subject, publicKey: "pQ", signCount: 0, backupEligible: false, backedUp: false });

/**
 * What `store` holds, read raw: each subject's list, and what each id's record names (its subject,
 * and whether it is pending, removed or a passkey), so a test sees what no read of passkeys mends.
 */
export async function heldState(
	store: PasskeyStore,
	subjects: readonly string[],
	ids: readonly string[],
) {
	const lists = await Promise.all(
		subjects.map(async (subject) => {
			const holder = (await store.subjects.read(keys.subject(subject))) as
				| { credentials?: string[] }
				| undefined;
			return [subject, holder?.credentials ?? []] as const;
		}),
	);
	const records = await Promise.all(
		ids.map(async (id) => {
			const record = (await store.credentials.read(keys.credential(id))) as
				| { subject?: string; pending?: boolean; removed?: boolean }
				| undefined;
			const as = record?.removed ? "removed" : record?.pending ? "pending" : "passkey";
			return [id, record && { subject: record.subject, as }] as const;
		}),
	);
	return { lists: Object.fromEntries(lists), records: Object.fromEntries(records) };
}

/**
 * Passkey records over `store`, what they write counted: each change of both spaces as one, each
 * run of such a change's decision, each write of one space alone, and each token made.
 */
export function jointOver(store: PasskeyStore, now: () => number = () => 1_000) {
	const counted = { together: 0, decisions: 0, single: 0, tokens: 0 };
	const one = (records: PasskeyRecords): PasskeyRecords => ({
		read: records.read,
		save: (...args) => {
			counted.single += 1;
			return records.save(...args);
		},
		update: (...args) => {
			counted.single += 1;
			return records.update(...args);
		},
	});
	const together = store.updateTogether.bind(store);
	const counting: PasskeyStore = {
		credentials: one(store.credentials),
		subjects: one(store.subjects),
		updateTogether: (named, p) => {
			counted.together += 1;
			const change = (read: Parameters<typeof p.change>[0]) => {
				counted.decisions += 1;
				return p.change(read);
			};
			return together(named, { watch: p.watch, change });
		},
	};
	const token = () => {
		counted.tokens += 1;
		return `t${counted.tokens}`;
	};
	const records = keptPasskeys(counting, token, now);
	const credentialFor = async (subject: string, id = freshKey()): Promise<Credential> => ({
		id,
		publicKey: "pQ",
		signCount: 0,
		userHandle: await records.handleFor(subject, freshKey()),
		backupEligible: false,
		backedUp: false,
	});
	return {
		records,
		counted,
		credentialFor,
		listOf: async (subject: string) => (await records.holder(subject))?.credentials ?? [],
		recordOf: (id: string) => store.credentials.read(keys.credential(id)),
		/** Keeps `record` for `id` as given, whatever it holds: as 0.18 left one, or a test needs. */
		keepAs: async (id: string, record: object) => {
			const key = keys.credential(id);
			if ((await store.credentials.save(key, stored(record), "endless")) === "exists") {
				await store.credentials.update(key, () => ({ value: stored(record) }));
			}
		},
		/** Keeps a live record of `subject`'s for `id` as 0.18 left one a registration failed between its writes: on no list. */
		orphanAs18: (id: string, subject: string) =>
			store.credentials.save(keys.credential(id), live18(subject), "endless"),
		/** Lists `ids` on the subject's holder as 0.18 left them, whatever their records hold. */
		listAs18: async (subject: string, ids: readonly string[]) => {
			await records.handleFor(subject, freshKey());
			await store.subjects.update(keys.subject(subject), (current) => ({
				value: stored({ ...(current as object), credentials: ids }),
			}));
		},
		/** Whether the subject's list names `id` exactly while its record names the subject, pending or a passkey. */
		agreed: async (subject: string, id: string) => {
			const record = (await store.credentials.read(keys.credential(id))) as
				| { subject?: string; removed?: boolean }
				| undefined;
			const held = record?.subject === subject && record.removed !== true;
			const listed = ((await records.holder(subject))?.credentials ?? []).includes(id);
			return held === listed;
		},
	};
}

/** `jointOver` the memory stores, which change both spaces as one. */
export function jointStores(now: () => number = () => 1_000) {
	const stores = memoryStores(now);
	return { stores, ...jointOver(stores.passkeys, now) };
}
