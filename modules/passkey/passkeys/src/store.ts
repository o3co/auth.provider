import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";

declare const storedPasskey: unique symbol;
/** A passkey record as the store keeps it: the store never reads it, and only passkeys opens it. */
export type StoredPasskey = { readonly [storedPasskey]: true };

declare const storedChallenge: unique symbol;
/** A challenge's record as the store keeps it: only passkeys opens it. */
export type StoredChallenge = { readonly [storedChallenge]: true };

/** Records by a key passkeys makes, each changed only from what it holds, kept without end. */
export interface PasskeyRecords {
	/**
	 * Keeps a key's first record for its subject, unless the key holds one (`exists`) or, where the
	 * Store fences saves past a subject's erasure, the subject is erased there (`erased`). passkeys
	 * always gives the subject. TODO(0.20, the remove step): `subject` required.
	 */
	save(
		key: string,
		record: StoredPasskey,
		lifetimeMs: "endless",
		subject?: string,
	): Promise<"created" | "exists" | "erased">;
	read(key: string): Promise<StoredPasskey | undefined>;
	/**
	 * Changes the record from what it holds; `change` runs again on a race, so it is pure; none
	 * leaves it. Nothing when gone, or, where the Store fences saves past a subject's erasure, when
	 * its subject is erased.
	 */
	update(
		key: string,
		change: (record: StoredPasskey) => { readonly value: StoredPasskey } | undefined,
	): Promise<{ readonly before: StoredPasskey; readonly after: StoredPasskey } | undefined>;
	/**
	 * Erases a subject's records here, where the Store can: optional in 0.20, required in 0.22. Both
	 * spaces' `erase` and `migrate` come together or none; a part refuses the boot.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key, each record read by passkeys' reading; optional as `erase` is. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

/** A record of the passkey store, as a change as one names it: its space, and its key. */
export interface PasskeyKey {
	readonly place: keyof PasskeyKeys;
	readonly key: string;
}

/** A record as a change as one reads it: its value, and the subject the Store keeps it for; none, kept raw. */
export type PasskeyRead = { readonly value: StoredPasskey; readonly subject?: string } | undefined;

/** What a change as one does to one record; its words are subject-records' joint change's. */
export type PasskeyOp =
	| {
			readonly kind: "create";
			readonly value: StoredPasskey;
			readonly lifetimeMs: "endless";
			readonly subject: string;
	  }
	| { readonly kind: "change"; readonly value: StoredPasskey }
	| { readonly kind: "remove" }
	| { readonly kind: "move"; readonly value: StoredPasskey; readonly to: string };

/** A record of a change as one: what it held, and holds after. */
export interface PasskeyChanged {
	readonly before: PasskeyRead;
	readonly after: PasskeyRead;
}

/** A change as one, whole: written, or refused at one record (`nth` in its list), nothing written. */
export type PasskeysAnswer =
	| {
			readonly kind: "written";
			readonly targets: readonly PasskeyChanged[];
			readonly watched: readonly PasskeyChanged[];
	  }
	| {
			readonly kind: "refused";
			readonly at: { readonly in: "targets" | "watched"; readonly nth: number };
			readonly why: "exists" | "erased" | "missing";
	  };

/** Keys of the passkey store, by space. */
export interface PasskeyKeys {
	readonly credentials: readonly string[];
	readonly subjects: readonly string[];
}

/** What records of both spaces changed as one held, by space: the keys named, then the watched ones, in order. */
export interface PasskeysRead {
	readonly credentials: readonly (StoredPasskey | undefined)[];
	readonly subjects: readonly (StoredPasskey | undefined)[];
}

/** The next of each record read, by space in the order read; none keeps it. */
export interface PasskeysNext {
	readonly credentials?: readonly ({ readonly value: StoredPasskey } | undefined)[];
	readonly subjects?: readonly ({ readonly value: StoredPasskey } | undefined)[];
}

/** One record of a change as one: what it held, and holds after. */
export interface ChangedPasskey {
	readonly before: StoredPasskey | undefined;
	readonly after: StoredPasskey | undefined;
}

/** Passkeys by credential, and each subject's handle and credentials, apart. Every call throws Unavailable when the place cannot tell. */
export interface PasskeyStore {
	readonly credentials: PasskeyRecords;
	readonly subjects: PasskeyRecords;
	/**
	 * Changes records of both spaces as one: those `keys` names, and those `watch` names (in either
	 * space) from what they hold. `change` answers the next of each, by space in the order read; it
	 * runs again on a race, so it is pure, and a record it leaves out is kept. Every record read is
	 * held to what was read; a record named twice is read once and written from one naming at most.
	 * Exactly one of this and `updateAsOne` is offered.
	 * @deprecated `updateAsOne`; removed in this release, once every Store offers it.
	 */
	updateTogether?(
		keys: PasskeyKeys,
		p: {
			readonly watch: (read: PasskeysRead) => Partial<PasskeyKeys>;
			readonly change: (read: PasskeysRead) => PasskeysNext;
		},
	): Promise<{
		readonly credentials: readonly ChangedPasskey[];
		readonly subjects: readonly ChangedPasskey[];
	}>;
	/**
	 * Changes records of both spaces as one: those `targets` names, and those `watch` names from what
	 * they hold, each by the op `decide` gives it, written as one, or refused at one record, nothing
	 * written; `decide` runs again on a race, so it is pure. Its words are subject-records' joint
	 * change's. Where the Store fences saves past a subject's erasure, a move from a subject whose
	 * tombstone alone stands is Unavailable.
	 */
	updateAsOne?(p: {
		readonly targets: readonly PasskeyKey[];
		readonly watch?: (read: readonly PasskeyRead[]) => readonly PasskeyKey[];
		readonly decide: (
			read: readonly PasskeyRead[],
			watched: readonly PasskeyRead[],
		) => {
			readonly targets?: readonly (PasskeyOp | undefined)[];
			readonly watched?: readonly (PasskeyOp | undefined)[];
		};
	}): Promise<PasskeysAnswer>;
}

export const passkeyStore = contract<PasskeyStore>("passkeys.passkey-store");

/** A passkey lost or come back would let a removed key in, or keep its owner out; a login reads one another request wrote. */
export const passkeyStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
} as const;

/** Challenges by the challenge, never kept in clear, each kept for its lifetime. Every call throws Unavailable when the place cannot tell. */
export interface ChallengeStore {
	/** Keeps a new challenge's record for its lifetime, unless the challenge holds one. */
	open(
		challenge: string,
		record: StoredChallenge,
		lifetimeMs: number,
	): Promise<"created" | "exists">;
	/** Puts `mark` in place of what the challenge holds, for the rest of its lifetime, and answers both. Nothing when gone. */
	take(
		challenge: string,
		mark: StoredChallenge,
	): Promise<{ readonly before: StoredChallenge; readonly after: StoredChallenge } | undefined>;
}

export const challengeStore = contract<ChallengeStore>("passkeys.challenge-store");

/** A challenge taken that came back could be answered twice; one lost to memory only fails its ceremony. */
export const challengeStoreNeeds = {
	survivesCrash: true,
	survivesFailover: true,
	/** Names derive from the challenge, so the place never keeps it in clear. */
	namesFromSecret: true,
} as const;
