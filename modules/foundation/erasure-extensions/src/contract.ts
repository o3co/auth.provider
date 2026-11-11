import { extensionPoint } from "@mod/kernel";

declare const made: unique symbol;
/** Made by `subject-records` alone, which erases; an eraser passes it on, never writes one. */
export type ReportMade = { readonly [made]: true };

/**
 * What erasing a subject did in one space, by the space's declared name: its records removed
 * under its tombstone (`erased`); new ones fenced by the tombstone, those kept ending by `until`,
 * a store-clock time (`fenced`); or not finished, with why (`stopped`).
 */
export type SpaceReport = ReportMade &
	(
		| { readonly kind: "erased"; readonly space: string; readonly removed: number }
		| { readonly kind: "fenced"; readonly space: string; readonly until: number }
		| { readonly kind: "stopped"; readonly space: string; readonly reason: string }
	);

/**
 * What putting one space's records written before indexing into the index did: indexed, or
 * removed as orphans proven to have no owner; or not finished, with why.
 */
export type MigrationReport = ReportMade &
	(
		| {
				readonly kind: "migrated";
				readonly space: string;
				readonly indexed: number;
				readonly removed: number;
		  }
		| { readonly kind: "stopped"; readonly space: string; readonly reason: string }
	);

/**
 * Whose a record written before indexing is, as its owner reads it: a subject's; an orphan, which
 * the owner proves has none, and which a migration removes; or unreadable, which proves nothing,
 * so the migration stops that space with `reason` and removes nothing.
 */
export type SubjectOf =
	| { readonly kind: "subject"; readonly subject: string }
	| { readonly kind: "orphan" }
	| { readonly kind: "unreadable"; readonly reason: string };

/**
 * The owner's reading of a record's subject from its key and its value as stored, so the store
 * holding it never opens the owner's value. It writes nothing; a lookup it makes may fail, and a
 * failure is `unreadable`, never `orphan`.
 */
export type SubjectReading = (key: string, value: unknown) => Promise<SubjectOf>;

/** An eraser's answer: its spaces' reports, and the logout notices it could not tell were delivered. */
export interface Erased {
	readonly reports: readonly SpaceReport[];
	/** Counted high where unsure; 0 for an eraser with no notices to lose. */
	readonly logoutGaps: number;
}

/**
 * A walk of a space by its declared name, removing what expired, as the tool hands it to the
 * eraser for a window or a migration; `keys` are the store's, passed back to the eraser's own
 * records, and `server` names the server a page ran on, so a walk starts over where it changes.
 */
export interface Walk {
	sweep(
		space: string,
		cursor?: string,
	): Promise<{
		readonly keys: readonly unknown[];
		readonly cursor?: string;
		readonly server: string;
	}>;
}

/**
 * Erases one owner's spaces of a subject's data, by its name, which those spaces' `erasedBy`
 * gives. A run cut short by `signal` answers `stopped` (`aborted`) for the spaces it did not finish.
 */
export interface Eraser {
	readonly name: string;
	/**
	 * Whether every space this eraser erases is held by a store with the erase ports: a statement
	 * of the stores behind it, known at build, not of a run. One that is not answers empty reports.
	 * Required in 0.20; optional, read as true, in 0.22; removed after.
	 */
	readonly erasable: boolean;
	/** The erasers, by name, whose runs this one's follow; account erasure orders them. */
	readonly after?: readonly string[];
	/** While the provider serves: writes the subject's tombstones and removes its records. */
	online(subject: string, signal: AbortSignal): Promise<Erased>;
	/** Under the maintenance key: the same for each subject, walking where an index cannot reach. */
	window(subjects: readonly string[], walk: Walk, signal: AbortSignal): Promise<Erased>;
	/** Once, under the maintenance key: puts the records written before indexing into the index. */
	migrate(walk: Walk, signal: AbortSignal): Promise<readonly MigrationReport[]>;
}

export const erasers = extensionPoint<Eraser>("erasure.erasers", {
	multiplicity: "keyed",
	keyOf: (eraser) => eraser.name,
});

/**
 * The marks account erasure keeps in the store's control record, by name. `enabled` holds `true`
 * and counts in any epoch it was written in; `journal` holds the erasure journal's header id and
 * last record number (`JournalMark`).
 */
export const erasureMarks = Object.freeze({
	enabled: "account-erasure.enabled",
	journal: "account-erasure.journal",
});

/** A store's control record as read for its marks, by name; this package reads no other part of it. */
export interface MarksRead {
	control(): Promise<{ readonly marks: Readonly<Record<string, unknown>> }>;
}

/**
 * Whether erasure is enabled, as a store's control record tells it: the `enabled` mark is there, in
 * any epoch, whatever it holds. Where no control record is offered (a store adapter that provides
 * none), nothing: a reader takes erasure as unknown, and it cannot be enabled.
 */
export function erasureEnabledFrom(control: MarksRead | undefined): {
	readonly erasureEnabled?: () => Promise<boolean>;
} {
	if (control === undefined) return {};
	return {
		erasureEnabled: async () => (await control.control()).marks[erasureMarks.enabled] !== undefined,
	};
}

/** The erasure journal's copy in the control record. */
export interface JournalMark {
	readonly id: string;
	readonly number: number;
}
