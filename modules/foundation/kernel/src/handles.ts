export interface Contract<T> {
	readonly kind: "contract";
	readonly label: string;
	/** The modules that may take it, by name; with none, any module may. */
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
