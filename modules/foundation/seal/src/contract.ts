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
