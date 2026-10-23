import { contract } from "@mod/kernel";

declare const storedPasskey: unique symbol;
/** A passkey record as the store keeps it: the store never reads it, and only passkeys opens it. */
export type StoredPasskey = { readonly [storedPasskey]: true };

declare const storedChallenge: unique symbol;
/** A challenge's record as the store keeps it: only passkeys opens it. */
export type StoredChallenge = { readonly [storedChallenge]: true };

/** Records by a key passkeys makes, each changed only from what it holds, kept without end. */
export interface PasskeyRecords {
	/** Keeps a key's first record, unless the key holds one. */
	save(key: string, record: StoredPasskey, lifetimeMs: "endless"): Promise<"created" | "exists">;
	read(key: string): Promise<StoredPasskey | undefined>;
	/** Changes the record from what it holds; `change` runs again on a race, so it is pure; none leaves it. Nothing when gone. */
	update(
		key: string,
		change: (record: StoredPasskey) => { readonly value: StoredPasskey } | undefined,
	): Promise<{ readonly before: StoredPasskey; readonly after: StoredPasskey } | undefined>;
}

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
	 * A place that cannot leaves it out.
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
