import { type Pkg, type Surface, surfacesOf } from "@mod/guard-imports";

/** One entry point of a package, and the names it exports that the package's card does not list. */
export interface Unlisted {
	readonly where: string;
	readonly entry: string;
	readonly names: readonly string[];
}

/** A name, or the name a call, a type's arguments, a member or an index open with. */
const opening = /^([A-Za-z_$][\w$]*)(?:[(<.[][\s\S]*)?$/;
/** An entry point, which names its default export. */
const entryPoint = /^\.\/[\w-]+$/;

/** The names a card lists: each backticked token in its Offers and Deprecated sections that is a name, opens with one, or is an entry point. */
export function listedOn(card: string): Set<string> {
	const listed = new Set<string>();
	let section = "";
	for (const line of card.split("\n")) {
		const heading = /^## (.+?)\s*$/.exec(line);
		if (heading) section = heading[1] ?? "";
		else if (section === "Offers" || section === "Deprecated") {
			for (const [, token] of line.matchAll(/`([^`]+)`/g)) {
				const text = token?.trim() ?? "";
				const name = entryPoint.test(text) ? text : opening.exec(text)?.[1];
				if (name) listed.add(name);
			}
		}
	}
	return listed;
}

/** An entry's exports the card does not list: each value, and each type no value carries, in turn. */
export function unlistedIn(surface: Surface, listed: ReadonlySet<string>): string[] {
	const carried = new Set<string>();
	const reach = (name: string): void => {
		for (const type of surface.carries.get(name) ?? []) {
			if (!carried.has(type)) {
				carried.add(type);
				reach(type);
			}
		}
	};
	for (const value of surface.values) reach(value);
	const types = [...surface.types].filter((type) => !carried.has(type));
	return [...surface.values, ...types].filter((name) => !listed.has(name));
}

/** Every package's entry points whose exports its card does not all list, by the entries its manifest names. */
export function unlistedExports(packages: readonly Pkg[]): Unlisted[] {
	const entries = new Set(packages.flatMap((p) => Object.keys(p.manifest.exports ?? {})));
	return [...entries].flatMap((entry) => {
		const surfaces = surfacesOf(packages, entry);
		return packages.flatMap((p) => {
			const surface = surfaces.get(p.name);
			const listed = listedOn(p.card ?? "");
			// A default is listed by its entry point's name; a `./module`'s is the module itself.
			const names = (surface ? unlistedIn(surface, listed) : []).filter(
				(name) => name !== "default" || (entry !== "./module" && !listed.has(entry)),
			);
			return names.length > 0 ? [{ where: p.name, entry, names }] : [];
		});
	});
}
