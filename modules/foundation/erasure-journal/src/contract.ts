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

/**
 * A subject whose erasure began, with who asked and when, whether it finished, its last number,
 * and the number of its last `begun` record: the later run's, where it was begun more than once.
 */
export interface JournalEntry {
	readonly subject: string;
	readonly requestedBy: string;
	readonly begunAt: number;
	readonly finished: boolean;
	readonly number: number;
	readonly begunNumber: number;
}

/**
 * The place held by the journal `hold` was asked of, released once (`held`); or held already by
 * another, named as the medium records its holder (`busy`): text for the operator, never parsed and
 * never judged live. A release the medium fails throws Unavailable; the hold may stay until it is
 * released.
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
	 * This journal holds its place until released, whatever the place holds (it holds before
	 * `create`); any other journal over the same place, in this process or another, answers `busy`,
	 * an answer and never Unavailable. A command opens one journal. While held, this journal's
	 * appends are made under the hold; one made outside it (another journal's, or this one's once
	 * its release began) throws Unavailable, and a caller appends only under a hold it took. With no
	 * hold anywhere, an append is still made. A hold is never broken on a guess (a pid, a time): one
	 * whose holder died stays until the medium or the operator releases it.
	 */
	hold(): Promise<JournalHold>;
}

export const erasureJournal = contract<ErasureJournal>("erasure-journal");
