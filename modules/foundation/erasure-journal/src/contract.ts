import { contract } from "@mod/kernel";

/**
 * The journal's content cannot be relied on: it has no header (`missing`), its last record does not
 * match its length or checksum (`torn`), or a record does not read (`corrupt`). An I/O failure is no
 * such state: it throws Unavailable, and the call can be made again.
 */
export interface Unusable {
	readonly kind: "unusable";
	readonly reason: "missing" | "torn" | "corrupt";
}

/** The journal's header: the random id it was created with, and its last record's number (0 for none). */
export interface JournalHeader {
	readonly id: string;
	readonly number: number;
}

/** A subject whose erasure began, with who asked and when, whether it finished, and its last number. */
export interface JournalEntry {
	readonly subject: string;
	readonly requestedBy: string;
	readonly begunAt: number;
	readonly finished: boolean;
	readonly number: number;
}

/**
 * The one record of account erasures for a deployment, appended to only. Records are numbered
 * from 1, each one more than the last; an answer to `begun` or `finished` means the record is
 * durable. Every call answers `Unusable` where the content cannot be relied on, and throws
 * Unavailable where the medium fails.
 */
export interface ErasureJournal {
	/** Creates the journal once, its header holding a new random id. */
	create(): Promise<
		{ readonly kind: "created"; readonly id: string } | { readonly kind: "exists" }
	>;
	header(): Promise<JournalHeader | Unusable>;
	/** Records that erasing `subject` began, asked by `requestedBy`. */
	begun(subject: string, requestedBy: string): Promise<{ readonly number: number } | Unusable>;
	/** Records that erasing `subject` finished. */
	finished(subject: string): Promise<{ readonly number: number } | Unusable>;
	/** Every subject whose erasure began, once each, in the order they began. */
	list(): Promise<readonly JournalEntry[] | Unusable>;
}

export const erasureJournal = contract<ErasureJournal>("erasure-journal");
