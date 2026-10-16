export interface Contract<T> {
	readonly kind: "contract";
	readonly label: string;
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

export function contract<T>(label: string): Contract<T> {
	return Object.freeze({ kind: "contract", label });
}

export function extensionPoint<T>(label: string, rule: ExtensionRule<T>): ExtensionPoint<T> {
	return Object.freeze({ kind: "extension-point", label, rule: Object.freeze(rule) });
}
