import { contract } from "@mod/kernel";

declare const storedLink: unique symbol;
/** Who an upstream identity is linked to, as the store keeps it: only users opens it. */
export type StoredLink = { readonly [storedLink]: true };

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
	save(key: string, record: T): Promise<"created" | "exists">;
	read(key: string): Promise<T | undefined>;
	/** Changes the record from what it holds, or leaves it on none; `change` runs again on a race, so it is pure. Nothing when gone. */
	update(
		key: string,
		change: (record: T) => Changed<T> | undefined,
	): Promise<{ readonly before: T; readonly after: T } | undefined>;
}

export type LinkStore = RecordStore<StoredLink>;
export type ContactStore = RecordStore<StoredContacts>;

export const linkStore = contract<LinkStore>("users.link-store");
export const contactStore = contract<ContactStore>("users.contact-store");

/** A link read to log someone in may have been removed by another request, so reads must be confirmed. */
export const linkStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	confirmedReads: true,
} as const;

/** Losing a verified contact would make its owner verify it again. */
export const contactStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
