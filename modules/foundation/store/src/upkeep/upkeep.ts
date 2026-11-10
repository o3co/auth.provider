import { contract } from "@mod/kernel";
import type { Guarantee, Json, Key, Space } from "../contract.ts";

/** An owner's value in the control record, with the epoch it was written in (null before any epoch). */
export interface Mark {
	readonly value: Json;
	readonly epoch: string | null;
}

/**
 * The one control record of a store's data. Every change is checked against its epoch, new on
 * each entry to maintenance and never one the data had, null where none ever was. `requires` names
 * the spaces every process must declare to start. `marks` are values their owners name, prefixed
 * with the owner's name as space names are; store keeps them and never reads them.
 */
export interface Control {
	readonly epoch: string | null;
	readonly maintenance: boolean;
	readonly requires: readonly string[];
	readonly marks: Readonly<Record<string, Mark>>;
}

/** Reading the control record, apart from changing it. */
export interface StoreControl {
	/** The control record, confirmed. */
	control(): Promise<Control>;
}

/**
 * Whether the store gives a set of guarantees now: checked, taken from what the operator declared
 * where the store could not check (those settings named), or not, with why. Where it gives them, a
 * witness of the server and its history: equal witnesses, the same server and history, nothing
 * evicted between; the store never compares them, its reader does.
 */
export type Honours =
	| { readonly kind: "verified"; readonly witness: string }
	| { readonly kind: "declared"; readonly settings: readonly string[]; readonly witness: string }
	| { readonly kind: "unmet"; readonly reasons: readonly string[] };

/** A space the store has seen declared, and whether any declaration may have held a subject's data. */
export interface KeptSpace {
	readonly name: string;
	readonly subjectDataEver: boolean;
}

/**
 * Keeping the store's data as a whole: the control record's changes, the ledger of spaces, the
 * guarantees as they stand, and a walk that removes what expired. A process whose epoch is not the
 * control record's changes nothing here either: each change is unavailable.
 */
export interface StoreUpkeep {
	/** Writes an owner's mark, in the present epoch, confirmed. */
	mark(name: string, value: Json): Promise<{ readonly kind: "marked" }>;
	/** Replaces `requires`, confirmed; only under the maintenance key, and never with none. */
	require(
		names: readonly string[],
	): Promise<{ readonly kind: "required" } | { readonly kind: "not-in-maintenance" }>;
	/** Sets the maintenance key and a new epoch, confirmed, in one write; this process takes the epoch. */
	enterMaintenance(): Promise<{ readonly kind: "entered"; readonly epoch: string }>;
	/** Lifts the maintenance key, confirmed; the epoch stays. */
	leaveMaintenance(): Promise<{ readonly kind: "left" }>;
	/** Every space ever declared to the store's data, until retired. */
	kept(): Promise<readonly KeptSpace[]>;
	/** Takes a space off the ledger, under the maintenance key alone; never one this process declares. */
	retire(
		name: string,
	): Promise<
		| { readonly kind: "retired" }
		| { readonly kind: "declared" }
		| { readonly kind: "missing" }
		| { readonly kind: "not-in-maintenance" }
	>;
	/** Checks again, on every call, whether the store gives these guarantees now. */
	honours(guarantees: readonly Guarantee[]): Promise<Honours>;
	/**
	 * A page of the space's live value keys, as `scan` walks, removing for good each expired one it
	 * meets, confirmed as a write; `server` names the server the page ran on, so a walker starts over
	 * when it changes.
	 */
	sweep(
		space: Space,
		cursor?: string,
	): Promise<{ readonly keys: readonly Key[]; readonly cursor?: string; readonly server: string }>;
}

/**
 * Its owner lets it go unprovided until 0.22: a taker reads a mark it cannot read as unknown, failing
 * closed, as long as store adapters of 0.19 provide none.
 */
export const storeControl = contract<StoreControl>("store.control", { optional: true });
export const storeUpkeep = contract<StoreUpkeep>("store.upkeep");
