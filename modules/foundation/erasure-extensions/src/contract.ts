import { extensionPoint } from "@mod/kernel";

declare const made: unique symbol;
/** Made by `records` alone, which erases and so can tell; an eraser passes it on, never writes one. */
export type MadeByRecords = { readonly [made]: true };

/**
 * What erasing a subject did in one space, by the space's declared name: its records removed
 * under its tombstone (`erased`); new ones fenced by the tombstone, those kept ending by `until`,
 * a store-clock time (`fenced`); or not finished, with why (`stopped`).
 */
export type SpaceReport = MadeByRecords &
	(
		| { readonly kind: "erased"; readonly space: string; readonly removed: number }
		| { readonly kind: "fenced"; readonly space: string; readonly until: number }
		| { readonly kind: "stopped"; readonly space: string; readonly reason: string }
	);

/**
 * What putting one space's records written before indexing into the index did: indexed, or
 * removed as orphans proven to have no owner; or not finished, with why.
 */
export type MigrationReport = MadeByRecords &
	(
		| {
				readonly kind: "migrated";
				readonly space: string;
				readonly indexed: number;
				readonly removed: number;
		  }
		| { readonly kind: "stopped"; readonly space: string; readonly reason: string }
	);

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

/** The erasure journal's copy in the control record. */
export interface JournalMark {
	readonly id: string;
	readonly number: number;
}
