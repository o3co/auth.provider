import { extensionPoint } from "@mod/kernel";

/** What an `id_token_hint` names: the End-User of an ID token this provider issued, or nothing it can take. */
export type HintReading =
	| { readonly kind: "subject"; readonly subject: string }
	| { readonly kind: "invalid" };

/** Judges an `id_token_hint`, contributed by the module that issues the ID tokens a hint may be. */
export interface HintReader {
	read(hint: string): Promise<HintReading>;
}

/** The one place a hint is judged: at most one contribution; with none, a hint is not read. */
export const hintReaders = extensionPoint<HintReader>("authorize.hint-reader", {
	multiplicity: "keyed",
	keyOf: () => "hint-reader",
});
