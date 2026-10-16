import { contract } from "@mod/kernel";

export type Opened =
	| { readonly kind: "opened"; readonly plain: string }
	| { readonly kind: "refused" };

export interface Seal {
	/** `context` names what the value belongs to; it is bound in, so a sealed value cannot be moved. */
	seal(plain: string, context: string): string;
	/** Throws Unavailable when the value was sealed with a key the ring no longer holds. */
	open(sealed: string, context: string): Opened;
}

export const seal = contract<Seal>("seal");
