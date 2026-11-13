import { extensionPoint } from "@mod/kernel";

declare const made: unique symbol;
/** A `SpaceReport`'s brand: made by `subject-records` alone, which erases; an eraser passes it on, never makes one. */
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
 * What erasing a subject did in a `pseudonymous` space, by its declared name: its owner claims that
 * nothing it keeps there under the subject's id, as its card bounds it, remains, beyond a record of
 * the owner's own that says only that the subject was erased there; `removed` counts what that run
 * removed. Made by the owner through `forgottenIn`, with no brand: it states no tombstone.
 */
export interface ForgottenReport {
	readonly kind: "forgotten";
	readonly space: string;
	readonly removed: number;
}

/** A `pseudonymous` space's report, by its declared name and what the run removed. */
export const forgottenIn = (space: string, removed: number): ForgottenReport => ({
	kind: "forgotten",
	space,
	removed,
});

/**
 * What putting one space's records or keyed sets written before indexing into the index did:
 * indexed, or removed as holding no subject's data (`removed`: orphans proven to have no owner,
 * those the owner kept elsewhere first among them); or not finished, with why.
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
 * An owner's answer that it cannot migrate yet, and why: not finished, as `stopped` is, the reason
 * saying what is missing or when to run again, and naming in the owner's words the part stopped
 * where it has several spaces. It names no space: its reader knows the eraser that answered it, and
 * the spaces through `erasedBy`. Made by the owner through `ownerStopped`, with no brand: it states
 * nothing `subject-records` wrote.
 */
export interface OwnerStopped {
	readonly kind: "owner-stopped";
	readonly reason: string;
}

/** An owner's stop of its migration, and why. */
export const ownerStopped = (reason: string): OwnerStopped => ({ kind: "owner-stopped", reason });

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

/**
 * The owner's reading of a keyed set's subject from its key alone: the owner never sees how a set
 * is kept. An orphan set is proven by its key's form, never by what the set holds. It writes
 * nothing; a lookup it makes may fail, and a failure is `unreadable`, never `orphan`; so is a
 * lookup's confirmed "none", as a parent no longer found proves nothing of the set.
 */
export type SetReading = (key: string) => Promise<SubjectOf>;

/**
 * The owner's step for a record its reading answered `orphan`, before the migration removes it:
 * it keeps what the record holds outside the space being migrated, where the owner still needs it.
 * It runs on the value a confirmed change held, never on an unconfirmed read; it writes only
 * outside that space; what it keeps is durable and confirmed before it returns, so the source may
 * go; and it is idempotent, as a rerun or a record changed meanwhile runs it again. A throw stops
 * the space, removing nothing more.
 */
export type Elsewhere = (key: string, value: unknown) => Promise<void>;

/** An eraser's answer: its spaces' reports, and the sessions it removed whose participants were never told. */
export interface Erased {
	readonly reports: readonly (SpaceReport | ForgottenReport)[];
	/**
	 * Sessions whose participants were never told, each counted once; summed across erasers, the
	 * sessions whose logout may not have reached all their RPs. High for a record it could not read,
	 * and for a session closing when erased (another eraser may count it too); low after an
	 * interrupted run. 0 for an eraser with no sessions to lose.
	 */
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
 * gives. A run cut short by `signal` answers `stopped` (`aborted`) for each space `subject-records`
 * reports; an eraser over no such space throws the signal's reason. An eraser that throws, abort
 * included, is not done, and running it again finishes it.
 */
export interface Eraser {
	readonly name: string;
	/**
	 * Whether this eraser can erase every space it erases on the stores behind it: known at build,
	 * not of a run. For a space `subject-records` reports, that its store has the erase ports. One
	 * that cannot answers empty reports.
	 * Required in 0.20; optional, read as true, in 0.22; removed after.
	 */
	readonly erasable: boolean;
	/** The erasers, by name, whose runs this one's follow: for account erasure to order them by. */
	readonly after?: readonly string[];
	/** While the provider serves: erases the subject's data in its spaces. */
	online(subject: string, signal: AbortSignal): Promise<Erased>;
	/** Under the maintenance key: the same for each subject, walking where an index cannot reach. */
	window(subjects: readonly string[], walk: Walk, signal: AbortSignal): Promise<Erased>;
	/** Once, under the maintenance key: puts the records written before indexing into the index. */
	migrate(walk: Walk, signal: AbortSignal): Promise<readonly (MigrationReport | OwnerStopped)[]>;
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
