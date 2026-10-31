/** What each composed module asks of the deployment, as its manifest declares it, rendered for the guide. */

/** One line a module asks of the deployment: shown always, or only where no adapter of it is composed; a value the operator decides where `decides`. */
export type Ask =
	| string
	| { readonly line: string; readonly decides?: true; readonly unadapted?: true };

/** What a package declares for the guide: its lines, the owner it adapts, and the name it registers under its owner. */
export interface Asked {
	readonly name: string;
	readonly asks?: readonly Ask[];
	readonly adapts?: string;
	readonly registersAs?: string;
}

/** The mark a line may hold: the composed adapters' names, else its own. */
const adaptersMark = "{adapters}";

/**
 * The guide's two lists, each line as `- …`, in the modules' order: what the composition asks of
 * the deployment (`chosen`), and the values the operator decides (`decides`).
 */
export function askedOf(
	modules: readonly string[],
	declared: readonly Asked[],
): { readonly chosen: string[]; readonly decides: string[] } {
	const composed = declared.filter((d) => modules.includes(d.name));
	const adaptersOf = (owner: string) => composed.filter((d) => d.adapts === owner);
	const chosen: string[] = [];
	const decides: string[] = [];
	for (const name of modules) {
		const own = composed.find((d) => d.name === name);
		const adapters = adaptersOf(name);
		const names = adapters.flatMap((a) => (a.registersAs ? [a.registersAs] : []));
		const filled = (names.length > 0 ? names : own?.registersAs ? [own.registersAs] : []).join(
			", ",
		);
		for (const ask of own?.asks ?? []) {
			const { line, decides: decided, unadapted } = typeof ask === "string" ? { line: ask } : ask;
			if (unadapted && adapters.length > 0) continue;
			(decided ? decides : chosen).push(`- ${line.replaceAll(adaptersMark, filled)}`);
		}
	}
	return { chosen, decides };
}
