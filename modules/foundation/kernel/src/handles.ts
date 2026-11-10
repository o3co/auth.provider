export interface Contract<T> {
	readonly kind: "contract";
	readonly label: string;
	/** The modules that may take it, by name; when omitted, any module may, and an empty list lets none. */
	readonly takenBy?: readonly string[];
	readonly __type?: T;
}

export type ExtensionRule<T> =
	| {
			readonly multiplicity: "one" | "some";
			/** What to compose when nothing is contributed (`compose @mod/x`): it follows the point's refusal then, and only then. */
			readonly missing?: string;
	  }
	| { readonly multiplicity: "many" }
	| { readonly multiplicity: "keyed"; readonly keyOf: (contribution: T) => string };

export interface ExtensionPoint<T> {
	readonly kind: "extension-point";
	readonly label: string;
	readonly rule: ExtensionRule<T>;
	readonly __type?: T;
}

/**
 * A contract a module takes where a module provides it: `find` answers its interface, or none where
 * none does, and no boot is refused for it. Only for what the taker does without by failing closed.
 */
export interface OptionalTake<T> {
	readonly kind: "optional";
	readonly label: string;
	readonly contract: Contract<T>;
}

/**
 * A handle a module takes: a contract, one taken optionally, or an extension point whatever its
 * contributions are. It is the handle itself, matched by identity, never by label (an optional
 * take by its contract's); a typed point is one as it stands.
 */
export type Handle =
	| Contract<unknown>
	| OptionalTake<unknown>
	| {
			readonly kind: "extension-point";
			readonly label: string;
			/** The rule the point's contributions are held to; what they are is erased. */
			readonly rule: {
				readonly multiplicity: ExtensionRule<never>["multiplicity"];
				readonly missing?: string;
			};
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

/** Takes `contract` optionally: the module builds whether or not a module provides it. */
export function optional<T>(contract: Contract<T>): OptionalTake<T> {
	return Object.freeze({ kind: "optional", label: contract.label, contract });
}

export function extensionPoint<T>(label: string, rule: ExtensionRule<T>): ExtensionPoint<T> {
	return Object.freeze({ kind: "extension-point", label, rule: Object.freeze(rule) });
}
