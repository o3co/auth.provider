import { contract, Unavailable } from "@mod/kernel";

declare const storedLink: unique symbol;
/** Who an upstream identity is linked to, as the store keeps it: only users opens it. */
export type StoredLink = { readonly [storedLink]: true };

declare const storedName: unique symbol;
/** The issuer an IdP name stands for, as the store keeps it: only users opens it. */
export type StoredName = { readonly [storedName]: true };

declare const storedContacts: unique symbol;
/** A subject's verified contacts, as the store keeps them: only users opens them. */
export type StoredContacts = { readonly [storedContacts]: true };

/** A record as a change leaves it. */
export interface Changed<T> {
	readonly value: T;
}

/** Records by key, kept without end, each changed only from what it holds. Every call throws Unavailable when the store cannot tell. */
export interface RecordStore<T> {
	/** Keeps a new record, unless the key holds one. */
	save(key: string, record: T, lifetimeMs: "endless"): Promise<"created" | "exists">;
	read(key: string): Promise<T | undefined>;
	/** Changes the record from what it holds, or leaves it on none; `change` runs again on a race, so it is pure. Nothing when gone. */
	update(
		key: string,
		change: (record: T) => Changed<T> | undefined,
	): Promise<{ readonly before: T; readonly after: T } | undefined>;
}

/**
 * Records of subjects by key, as `RecordStore`, each saved with the subject it is kept for, last: a
 * store that keeps the subject apart (to find and erase a subject's records) takes it; one that does
 * not may ignore it.
 */
export interface SubjectRecordStore<T> extends Omit<RecordStore<T>, "save"> {
	/** Keeps a new record for its subject, unless the key holds one. */
	save(
		key: string,
		record: T,
		lifetimeMs: "endless",
		subject: string,
	): Promise<"created" | "exists">;
}

/**
 * Changes the record, or saves `first` where there is none; one saved meanwhile is changed from what it holds.
 * @deprecated A helper the package writes its own stores with, exported by mistake; nothing replaces it, copy it. A later release removes it.
 */
export async function written<T>(
	store: RecordStore<T>,
	key: string,
	first: T,
	change: (record: T) => Changed<T> | undefined,
): Promise<{ readonly before: T | undefined; readonly after: T }> {
	const changed = await store.update(key, change);
	if (changed) return changed;
	if ((await store.save(key, first, "endless")) === "created")
		return { before: undefined, after: first };
	const again = await store.update(key, change);
	// The key held a record a moment ago, and records never end.
	if (!again) throw new Unavailable("users");
	return again;
}

export type LinkStore = SubjectRecordStore<StoredLink> & {
	/**
	 * The IdP names' own records, apart from the links: offered with `unowned`, or neither. Optional
	 * in 0.20, without it names keeping their records in the link space alone; required in 0.22.
	 */
	readonly names?: NameStore;
	/**
	 * Saves an IdP name's record in the link space, which holds no subject, unless the key holds one;
	 * `closed` where the link space keeps no such record any more, `names` then keeping it. Offered
	 * with `names`, or neither.
	 * @deprecated Names' records from before they moved out of the link space; removed in 0.22, when
	 * `names` is required.
	 */
	readonly unowned?: (
		key: string,
		record: StoredName,
		lifetimeMs: "endless",
	) => Promise<"created" | "exists" | "closed">;
};
export type ContactStore = SubjectRecordStore<StoredContacts>;
/** IdP names' records, apart from the links. */
export type NameStore = RecordStore<StoredName>;

export const linkStore = contract<LinkStore>("users.link-store");
export const contactStore = contract<ContactStore>("users.contact-store");

/** A link read to log someone in may have been removed by another request, so reads must be confirmed. */
export const linkStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
} as const;

/**
 * A name's record holds the issuer a boot judges the name by: lost or come back, a name could stand
 * for another issuer unnoticed; a move another instance wrote must be read.
 */
export interface NameStoreNeeds {
	readonly neverEvicted: true;
	readonly survivesCrash: true;
	readonly survivesFailover: true;
	readonly confirmedReads: true;
}

/** Losing a verified contact would make its owner verify it again. */
export const contactStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
