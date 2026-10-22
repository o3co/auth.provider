import { completedWith, type Declared, type Package } from "./declared.ts";
import { kinds } from "./kinds.ts";

/** What to compose: features in named groups, an adapter (or the owner itself) by axis owner, and anything added. */
export interface Selection {
	readonly features: Readonly<Record<string, readonly string[]>>;
	readonly axes?: Readonly<Record<string, string>>;
	readonly add?: readonly string[];
}

/** The axis owner a package adapts to or replaces. */
const axisOf = (p: Package | undefined) => p?.replaces ?? p?.adapts;

/** Each axis's adapters, by owner; the default is the one declaring it, or else the only one (of the workspace's, where it has any). */
export function axesIn(declared: Declared) {
	const adapters = new Map<string, Package[]>();
	for (const p of declared.packages.values()) {
		const owner = axisOf(p);
		if (owner !== undefined) adapters.set(owner, [...(adapters.get(owner) ?? []), p]);
	}
	const defaultOf = (owner: string) => {
		const of = adapters.get(owner) ?? [];
		// An adapter declared outside never takes the place of the workspace's only one.
		const ours = of.filter((p) => !p.outside);
		const only = ours.length > 0 ? ours : of;
		return (of.find((p) => p.default) ?? (only.length === 1 ? only[0] : undefined))?.name;
	};
	/** The adapter declared the default that replaces an owner: it composes in the owner's place, a module or not. */
	const replacingOf = (owner: string) =>
		(adapters.get(owner) ?? []).find((p) => p.default && p.replaces === owner)?.name;
	return { adapters, defaultOf, replacingOf };
}

export const addableOf = (declared: Declared) =>
	[...declared.packages.values()]
		.filter((p) => p.module && (p.kind === kinds.feature || p.kind === kinds.adapter))
		.map((p) => p.name)
		.sort();

/** Each name the workspace lacks, once, first named first. */
const absentFrom = (declared: Declared, names: readonly string[]) =>
	names
		.filter((n, i, all) => all.indexOf(n) === i && !declared.packages.has(n))
		.map((n) => `${n}: not in the workspace`);

/** Why each name cannot be selected, or none. */
function refusals(declared: Declared, selection: Selection): string[] {
	const { adapters } = axesIn(declared);
	const known = (name: string) => declared.packages.get(name);
	const grouped = Object.values(selection.features).flat();
	const added = selection.add ?? [];
	const axes = Object.entries(selection.axes ?? {});
	return [
		...absentFrom(declared, [...grouped, ...added, ...axes.flat()]),
		...grouped
			.filter((n) => known(n) && known(n)?.kind !== kinds.feature)
			.map((n) => `${n}: not a feature`),
		...added
			.filter((n) => known(n) && !addableOf(declared).includes(n))
			.map((n) => `${n}: not a feature or an adapter with a module`),
		...axes
			.filter(([owner]) => known(owner) && !adapters.has(owner))
			.map(([owner]) => `${owner}: not an axis's owner`),
		...axes
			.filter(([owner, chosen]) => adapters.has(owner) && known(chosen) && chosen !== owner)
			.filter(([owner, chosen]) => axisOf(known(chosen)) !== owner)
			.map(([owner, chosen]) => `${chosen}: not an adapter of ${owner}`),
		...axes
			.filter(([owner, chosen]) => adapters.has(owner) && chosen === owner && !known(owner)?.module)
			.map(
				([owner]) =>
					`axes.${owner} = ${owner}: the owner has no module, so it cannot serve its own axis`,
			),
	];
}

/** A selection's modules, first reached first: what it names and needs, each composed axis's chosen
 * adapter or default (none where another adapter of it is there), wirings and bridges; replaced owners left out. */
export function composedWith(declared: Declared, selection: Selection): string[] {
	const refused = refusals(declared, selection);
	if (refused.length > 0) throw new Error(refused.join("; "));
	return composing(
		declared,
		[...Object.values(selection.features).flat(), ...(selection.add ?? [])],
		selection.axes ?? {},
	);
}

/** The modules given and what they need to run, in turn, then wirings and bridges; owners a reached adapter replaces left out; of axis defaults, only one declared to replace its owner. Refuses, naming each, a name the workspace lacks. */
export function neededWith(declared: Declared, modules: readonly string[]): string[] {
	const absent = absentFrom(declared, modules);
	if (absent.length > 0) throw new Error(absent.join("; "));
	return composing(declared, modules, {}, { defaults: false });
}

function composing(
	declared: Declared,
	start: readonly string[],
	chosen: Readonly<Record<string, string>>,
	{ defaults } = { defaults: true },
): string[] {
	const { adapters, defaultOf, replacingOf } = axesIn(declared);
	const runs = (name: string) => {
		const p = declared.packages.get(name);
		return p?.kind === kinds.foundation || p?.kind === kinds.feature;
	};
	/** Every package reached, a module or not: an axis owner reached is composed. */
	const reached: string[] = [];
	const reach = (name: string) => {
		if (!reached.includes(name)) reached.push(name);
	};
	for (const name of start) reach(name);
	for (let size = -1; size !== reached.length; ) {
		size = reached.length;
		for (const name of reached)
			for (const need of declared.packages.get(name)?.needs ?? []) {
				// An axis owner is reached whatever its kind, as the kernel: its axis then applies.
				if (runs(need) || adapters.has(need)) reach(need);
			}
		for (const owner of reached.filter((name) => adapters.has(name))) {
			const pick = chosen[owner];
			if (pick !== undefined) {
				if (pick !== owner) reach(pick);
			} else if (!(adapters.get(owner) ?? []).some((a) => reached.includes(a.name))) {
				const fallback = defaults ? defaultOf(owner) : replacingOf(owner);
				if (fallback !== undefined) reach(fallback);
			}
		}
		// An axis owner reached counts for bridges, as a module does, whether it has one or not.
		const joined = reached.filter(
			(name) => declared.packages.get(name)?.module || adapters.has(name),
		);
		for (const name of completedWith(declared, joined)) reach(name);
	}
	const replaced = new Set(reached.flatMap((name) => declared.packages.get(name)?.replaces ?? []));
	return reached.filter((name) => declared.packages.get(name)?.module && !replaced.has(name));
}

/** The modules given, owners a declared default replaces swapped for it (still counted for bridges), then wirings and bridges. */
export function completedOf(declared: Declared, modules: readonly string[]): string[] {
	const { replacingOf } = axesIn(declared);
	// An owner named brings its default; an adapter named brings the owner it replaces, for bridges.
	const swapped = modules.flatMap((name) => {
		const by = replacingOf(name);
		const owner = declared.packages.get(name)?.replaces;
		const missing = (other: string | undefined) =>
			other === undefined || modules.includes(other) ? [] : [other];
		return [name, ...missing(by), ...missing(owner)];
	});
	const replaced = new Set(swapped.flatMap((name) => declared.packages.get(name)?.replaces ?? []));
	return completedWith(declared, swapped).filter((name) => !replaced.has(name));
}

/** The full template: every foundation and feature with a module that does not opt in, and what is added. */
export function fullWith(declared: Declared, add: readonly string[] = []): string[] {
	const refused = refusals(declared, { features: {}, add });
	if (refused.length > 0) throw new Error(refused.join("; "));
	const base = [...declared.packages.values()]
		.filter(
			(p) => p.module && !p.optIn && (p.kind === kinds.foundation || p.kind === kinds.feature),
		)
		.map((p) => p.name);
	return composing(declared, [...base, ...add], {});
}

/** The features that opt in: the full template leaves them out until added. */
export const optInsOf = (declared: Declared) =>
	[...declared.packages.values()]
		.filter((p) => p.optIn && p.kind === kinds.feature)
		.map((p) => p.name);
