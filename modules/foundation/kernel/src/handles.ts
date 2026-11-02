export interface Contract<T> {
	readonly kind: "contract";
	readonly label: string;
	/** The modules that may take it, by name; when omitted, any module may, and an empty list lets none. */
	readonly takenBy?: readonly string[];
	readonly __type?: T;
}

export type ExtensionRule<T> =
	| { readonly multiplicity: "one" | "some" | "many" }
	| { readonly multiplicity: "keyed"; readonly keyOf: (contribution: T) => string };

export interface ExtensionPoint<T> {
	readonly kind: "extension-point";
	readonly label: string;
	readonly rule: ExtensionRule<T>;
	readonly __type?: T;
}

/**
 * A handle a module takes: a contract, or an extension point whatever its contributions are. It is
 * the handle itself, matched by identity, never by label; a typed point is one as it stands.
 */
export type Handle =
	| Contract<unknown>
	| {
			readonly kind: "extension-point";
			readonly label: string;
			/** The rule the point's contributions are held to; what they are is erased. */
			readonly rule: { readonly multiplicity: ExtensionRule<never>["multiplicity"] };
	  };

export function contract<T>(
	label: string,
	options: { readonly takenBy?: readonly string[] } = {},
): Contract<T> {
	const { takenBy } = options;
	return Object.freeze({
		kind: "contract",
		label,
		...(takenBy === undefined ? {} : { takenBy: Object.freeze([...takenBy]) }),
	});
}

export function extensionPoint<T>(label: string, rule: ExtensionRule<T>): ExtensionPoint<T> {
	return Object.freeze({ kind: "extension-point", label, rule: Object.freeze(rule) });
}
