/** What was recorded of a package outside the release when the app was generated. */
export interface Recorded {
	readonly name: string;
	readonly version: string;
	readonly integrity: string;
}

/** The same, with the dependencies its manifest declares, as the lockfile is held to them. */
export interface OutsideRecord extends Recorded {
	readonly dependencies: Readonly<Record<string, string>>;
	readonly optionalDependencies: Readonly<Record<string, string>>;
	readonly peerDependencies: Readonly<Record<string, string>>;
	readonly peerDependenciesMeta: Readonly<Record<string, { readonly optional?: boolean }>>;
}

export function recordOf(text: string, name: string): Recorded;

export function refusals(
	text: string,
	records: readonly OutsideRecord[],
	overrides: Readonly<Record<string, string>>,
): string[];
