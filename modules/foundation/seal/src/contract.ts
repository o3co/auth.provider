import { contract, extensionPoint } from "@mod/kernel";

export type Opened =
	/** `stale`: sealed by a `previous` key; seal it again when writing it anyway. */
	| { readonly kind: "opened"; readonly plain: string; readonly stale?: true }
	| { readonly kind: "refused" };

export interface Seal {
	/** `context` names what the value belongs to; it is bound in, so a sealed value cannot be moved. */
	seal(plain: string, context: string): string;
	/** Throws Unavailable when the value was sealed with a key the ring no longer holds. */
	open(sealed: string, context: string): Opened;
}

export const seal = contract<Seal>("seal");

/** A holder of long-lived sealed values: walks its own, sealing again what is stale. */
export interface Resealer {
	readonly name: string;
	/** `left`: values it could not open, a key gone among them. */
	reseal(): Promise<{ readonly resealed: number; readonly left: number }>;
}

export const resealers = extensionPoint<Resealer>("seal.resealers", {
	multiplicity: "keyed",
	keyOf: (resealer) => resealer.name,
});

export type Resealed =
	| { readonly name: string; readonly resealed: number; readonly left: number }
	| { readonly name: string; readonly failed: true };

/** Each holder's counts, in name order; one that fails is told and the rest still run. */
export interface Resealing {
	reseal(): Promise<readonly Resealed[]>;
}

export const resealing = contract<Resealing>("seal.resealing");

/**
 * The reseal run as the app's `reseal` script calls it: each holder's line, then whether previous
 * keys may be retired. `code`: 0 when no holder failed and none resealed or left a value; 1 when a
 * holder failed; 2 when values no key opens remain; 3 when values were sealed again, as a walk across a
 * failover may miss some, so run again; 64 for any argument, as it takes none. Lines carry holder
 * names and counts alone, never an id, a value or an error's words.
 */
export interface ResealRun {
	run(
		args: readonly string[],
	): Promise<{ readonly lines: readonly string[]; readonly code: number }>;
}

export const resealRun = contract<ResealRun>("seal.reseal-run");
