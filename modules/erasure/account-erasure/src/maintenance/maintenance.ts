import { contract } from "@mod/kernel";

/** A value an owner's mark holds: plain JSON data. */
export type MarkValue =
	| string
	| number
	| boolean
	| null
	| readonly MarkValue[]
	| { readonly [name: string]: MarkValue };

/** An owner's mark, with the epoch it was written in (null before any epoch). */
export interface Mark {
	readonly value: MarkValue;
	readonly epoch: string | null;
}

/** The control record as erasure reads it. */
export interface MaintenanceRecord {
	readonly epoch: string | null;
	/** Whether the maintenance key is held. */
	readonly maintenance: boolean;
	/** The spaces every process must declare to start. */
	readonly requires: readonly string[];
	readonly marks: Readonly<Record<string, Mark>>;
}

/** A space on the ledger, and whether any declaration of it may have held a subject's data. */
export interface KeptSpace {
	readonly name: string;
	readonly subjectDataEver: boolean;
}

/** A guarantee a space may declare. */
export type Guarantee = "no-eviction" | "durable" | "replicated" | "confirmed-reads";

/** Whether the store gives a set of guarantees now, with a witness of the server and its history where it does. */
export type Honours =
	| { readonly kind: "verified"; readonly witness: string }
	| { readonly kind: "declared"; readonly settings: readonly string[]; readonly witness: string }
	| { readonly kind: "unmet"; readonly reasons: readonly string[] };

/** What a space holds of a subject's data, as its declaration says. */
export type SubjectData =
	| "online-indexed"
	| "online-keyed"
	| "bounded"
	| "window"
	| "none"
	| "pseudonymous"
	| "retained"
	| "internal";

/** A space this process declares, with its erasure fields. */
export interface DeclaredSpace {
	readonly name: string;
	readonly subjectData: SubjectData;
	readonly erasedBy?: string;
	readonly boundedMs?: number;
	readonly requiredOnceErasing?: boolean;
}

/** The phase records are in. */
export type Phase = "reader" | "indexed";

/** Whether another process is attached to the store's data now. */
export type Alone =
	| { readonly kind: "alone" }
	| { readonly kind: "accompanied"; readonly count: number }
	| { readonly kind: "unchecked"; readonly reasons: readonly string[] };

/**
 * A page of the walk of a kept space, in erasure's words: about how many live keys it met (exact
 * only at zero), how many of them endless, the latest end among the rest, and, on the walk's first
 * page alone, the space's generation; never a key.
 */
export interface KeptWalkPage {
	readonly kind: "page";
	readonly live: number;
	readonly endless: number;
	readonly latestEnd?: number;
	readonly generation?: string;
	readonly cursor?: string;
	readonly server: string;
}

/**
 * What erasure needs of the store's data as a whole, in erasure's words; its wiring alone provides
 * it. A process whose epoch is not the record's changes nothing through it: each change is
 * unavailable.
 */
export interface ErasureMaintenance {
	/** The control record, confirmed. */
	record(): Promise<MaintenanceRecord>;
	/** Sets the maintenance key and a new epoch in one write; this process takes the epoch. */
	enter(): Promise<{ readonly kind: "entered"; readonly epoch: string }>;
	/** Lifts the maintenance key; the epoch stays. */
	leave(): Promise<{ readonly kind: "left" }>;
	/** Writes an owner's mark in the present epoch, confirmed. */
	mark(name: string, value: MarkValue): Promise<{ readonly kind: "marked" }>;
	/** Replaces the spaces required, never with none; outside the key, `not-in-maintenance`. */
	require(
		names: readonly string[],
	): Promise<{ readonly kind: "required" } | { readonly kind: "not-in-maintenance" }>;
	/** Every space ever declared to the data, until retired. */
	kept(): Promise<readonly KeptSpace[]>;
	/**
	 * Takes a space off the ledger as of the generation a walk read: `retired`, or `declared` (this
	 * process declares it), `redeclared` (declared since), `missing`, `not-in-maintenance`.
	 */
	retire(
		name: string,
		generation: string,
	): Promise<
		| { readonly kind: "retired" }
		| { readonly kind: "declared" }
		| { readonly kind: "redeclared" }
		| { readonly kind: "missing" }
		| { readonly kind: "not-in-maintenance" }
	>;
	/**
	 * A page of the walk of a kept space this process doesn't declare, by its name, under the key
	 * alone; or `declared`, `missing`, `not-in-maintenance`. Where the store offers no such walk,
	 * none is offered here, and nothing is retired.
	 */
	sweepKept?(
		name: string,
		cursor?: string,
	): Promise<
		| KeptWalkPage
		| { readonly kind: "declared" }
		| { readonly kind: "missing" }
		| { readonly kind: "not-in-maintenance" }
	>;
	/** Whether the store gives these guarantees now, checked anew. */
	honours(guarantees: readonly Guarantee[]): Promise<Honours>;
	/**
	 * A page of the walk of a space, by its declared name, removing for good each expired key it
	 * meets: the page's live keys, opaque here and only handed on to an eraser, the next cursor, and
	 * the server it ran on.
	 */
	sweep(
		space: string,
		cursor?: string,
	): Promise<{
		readonly keys: readonly unknown[];
		readonly cursor?: string;
		readonly server: string;
	}>;
	/** The phase records are in. */
	phase(): Promise<Phase>;
	/** Turns records indexed: under the key alone, where the store writes records of two partitions as one. */
	writePhase(): Promise<
		| { readonly kind: "written" }
		| { readonly kind: "not-in-maintenance" }
		| { readonly kind: "not-paired" }
	>;
	/** Whether another process is attached to the store's data now; unavailable where the read is disturbed. */
	alone(): Promise<Alone>;
	/** The spaces this process declares, in declaration order: each one's name and erasure fields. */
	declared(): readonly DeclaredSpace[];
}

/** Taken by account-erasure alone; its wiring provides it. */
export const erasureMaintenance = contract<ErasureMaintenance>("account-erasure.maintenance", {
	takenBy: ["account-erasure"],
});
