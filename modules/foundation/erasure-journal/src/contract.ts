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
 * The journal held for one process, released once (`held`); or held already by another, named as
 * the medium records its holder (`busy`): text for the operator, never parsed and never judged live.
 */
export type JournalHold =
	| { readonly kind: "held"; release(): Promise<void> }
	| { readonly kind: "busy"; readonly holder: string };

/**
 * The one record of account erasures for a deployment, appended to only. Records are numbered
 * from 1, each one more than the last; an answer to `begun` or `finished` means the record is
 * durable. Every call but `hold` answers `Unusable` where the content cannot be relied on; every
 * call throws Unavailable where the medium fails.
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
	/**
	 * Holds the journal for this process until released, whatever its content (it holds before
	 * `create`). While held, this journal's appends are made under the hold; an append made outside
	 * it throws Unavailable. A held journal answers `busy`, an answer and never Unavailable. A hold is
	 * never broken on a guess (a pid, a time): one whose holder died stays until the medium or the
	 * operator releases it. Optional in this release, then required.
	 */
	hold?(): Promise<JournalHold>;
}

export const erasureJournal = contract<ErasureJournal>("erasure-journal");
