import { kinds, mayNeed } from "@mod/kinds";
import { axesIn } from "./composed.ts";
import type { Declared, Package } from "./declared.ts";

/** What a package declared outside the workspace says of itself, in the words composing reads. */
export interface Declaration {
	readonly name: string;
	readonly kind: string;
	/** The modules it needs to run, each declared in the workspace or beside it. */
	readonly needs: readonly string[];
	readonly optIn?: true;
	readonly replaces?: string;
	readonly adapts?: string;
	readonly default?: true;
	readonly wires?: string;
	readonly joins?: readonly string[];
}

/** The kinds a package declared outside the workspace may be. */
const outsideKinds: readonly string[] = [kinds.feature, kinds.adapter, kinds.wiring];

/** Each field a kind alone takes, and the words naming whose it is. */
const fieldsOf = [
	["replaces", [kinds.adapter], "an adapter's"],
	["adapts", [kinds.adapter], "an adapter's"],
	["default", [kinds.adapter], "an adapter's"],
	["optIn", [kinds.feature], "a feature's"],
	["wires", [kinds.wiring], "a wiring's"],
	["joins", [kinds.feature, kinds.adapter], "a feature's or an adapter's"],
] as const;

const a = (word: string) => (/^[aeiou]/.test(word) ? `an ${word}` : `a ${word}`);

/** Why each declaration cannot stand beside the workspace, by its shape alone: none of the workspace's own packages is read this way. */
function shapeRefusals(declared: Declared, outside: readonly Declaration[]): string[] {
	const named = new Set(outside.map((d) => d.name));
	const kindOf = (name: string) =>
		declared.packages.get(name)?.kind ?? outside.find((d) => d.name === name)?.kind;
	return outside.flatMap((d, i): string[] => {
		if (declared.packages.has(d.name)) return [`${d.name}: declared in the workspace`];
		if (outside.findIndex((o) => o.name === d.name) !== i) return [`${d.name}: declared twice`];
		if (!outsideKinds.includes(d.kind)) {
			return [`${d.name}: kind ${d.kind} is not one of ${outsideKinds.join(", ")}`];
		}
		const fields = fieldsOf
			.filter(([field, takers]) => d[field] !== undefined && !takers.some((k) => k === d.kind))
			.map(([field, , whose]) => `${d.name}: ${field} is ${whose}`);
		const needs = d.needs.flatMap((need) => {
			const kind = kindOf(need);
			if (!declared.packages.has(need) && !named.has(need)) {
				return [`${d.name}: needs ${need}, which is not declared`];
			}
			if (kind === undefined || !mayNeed(d.kind, kind)) {
				return [
					`${d.name}: ${a(d.kind)} may not need ${need}, ${kind ? a(kind) : "which has no kind"}`,
				];
			}
			if (d.kind === kinds.feature && declared.packages.get(need)?.forWiring) {
				return [`${d.name}: a feature may not need ${need}, which declares forWiring`];
			}
			return [];
		});
		return [...fields, ...needs, ...kindRefusals(d, declared, outside)];
	});
}

/** What an adapter's or a wiring's declaration must say. */
function kindRefusals(d: Declaration, declared: Declared, outside: readonly Declaration[]) {
	if (d.kind === kinds.adapter) {
		if (d.replaces !== undefined && d.adapts !== undefined)
			return [`${d.name}: declares replaces and adapts`];
		if (d.replaces === undefined && d.adapts === undefined) {
			return [`${d.name}: declares neither replaces nor adapts`];
		}
		const owner = d.replaces ?? d.adapts;
		if (d.default && owner !== undefined && declared.packages.has(owner)) {
			return [`${d.name}: declares the default of ${owner}, an axis the workspace owns`];
		}
	}
	if (d.kind === kinds.wiring) {
		if (d.wires === undefined) return [`${d.name}: wires no feature`];
		if (!outside.some((o) => o.name === d.wires && o.kind === kinds.feature)) {
			return [`${d.name}: wires ${d.wires}, which is not an outside feature`];
		}
	}
	return [];
}

const packageOf = (d: Declaration): Package => ({
	name: d.name,
	kind: d.kind,
	module: true,
	needs: d.needs,
	optIn: d.optIn === true,
	...(d.replaces !== undefined ? { replaces: d.replaces } : {}),
	...(d.adapts !== undefined ? { adapts: d.adapts } : {}),
	default: d.default === true,
	forWiring: false,
	outside: true,
});

/** Why the packages, the workspace's and those beside it, cannot be composed together: rules the workspace's own packages already keep. */
function graphRefusals(declared: Declared): string[] {
	const { packages } = declared;
	const absent = (name: string, field: string, targets: readonly string[]) =>
		targets
			.filter((t) => !packages.has(t))
			.map((t) => `${name}: ${field} ${t}, which is not declared`);
	const named = [
		...[...packages.values()].flatMap((p) => [
			...absent(p.name, "replaces", p.replaces ? [p.replaces] : []),
			...absent(p.name, "adapts", p.adapts ? [p.adapts] : []),
		]),
		...declared.bridges.flatMap(({ bridge, joins }) => absent(bridge, "joins", joins)),
		...[...declared.wirings].flatMap(([feature, wirings]) =>
			wirings.flatMap((w) => absent(w, "wires", [feature])),
		),
	];
	const { adapters, defaultOf } = axesIn(declared);
	const axes = [...adapters].flatMap(([owner, of]) => {
		const defaults = of.filter((p) => p.default).length;
		if (defaults > 1) return [`${owner}: ${defaults} defaults among its adapters`];
		if (of.length > 1 && defaultOf(owner) === undefined) {
			return [`${owner}: no default among its ${of.length} adapters`];
		}
		return [];
	});
	return [...named, ...axes, ...cycles(declared)];
}

/** A cycle of needs and joins among the packages declared, if any: a dependency on what is not declared (an npm package) is no edge. */
function cycles(declared: Declared): string[] {
	const edges = new Map<string, string[]>();
	for (const p of declared.packages.values()) {
		edges.set(
			p.name,
			p.needs.filter((n) => declared.packages.has(n)),
		);
	}
	for (const { bridge, joins } of declared.bridges) {
		edges.set(bridge, [
			...(edges.get(bridge) ?? []),
			...joins.filter((j) => declared.packages.has(j)),
		]);
	}
	const done = new Set<string>();
	const walk = (name: string, path: readonly string[]): string[] | undefined => {
		const at = path.indexOf(name);
		if (at >= 0) return [...path.slice(at), name];
		if (done.has(name)) return undefined;
		for (const next of edges.get(name) ?? []) {
			const found = walk(next, [...path, name]);
			if (found) return found;
		}
		done.add(name);
		return undefined;
	};
	for (const name of edges.keys()) {
		const found = walk(name, []);
		if (found) return [`a cycle: ${found.join(" -> ")}`];
	}
	return [];
}

/**
 * The workspace's declarations with those of packages declared outside it, each as a module: what
 * each declaration says is checked first (its kind, the fields its kind takes, its needs and their
 * direction, its axis, the feature it wires), then the graph of all of them together (each name a
 * package declares is declared, each axis has one default, no cycle). Refuses, naming each.
 */
export function declaredWith(declared: Declared, outside: readonly Declaration[]): Declared {
	const shape = shapeRefusals(declared, outside);
	if (shape.length > 0) throw new Error(shape.join("; "));
	const all = [...declared.packages.values(), ...outside.map(packageOf)].sort((x, y) =>
		x.name < y.name ? -1 : x.name > y.name ? 1 : 0,
	);
	const wirings = new Map(declared.wirings);
	for (const { name, wires } of outside) {
		if (wires !== undefined) wirings.set(wires, [...(wirings.get(wires) ?? []), name].sort());
	}
	const bridges = [
		...declared.bridges,
		...outside.flatMap(({ name, joins }) => (joins ? [{ joins, bridge: name }] : [])),
	].sort((x, y) => (x.bridge < y.bridge ? -1 : x.bridge > y.bridge ? 1 : 0));
	const merged: Declared = { wirings, bridges, packages: new Map(all.map((p) => [p.name, p])) };
	const graph = graphRefusals(merged);
	if (graph.length > 0) throw new Error(graph.join("; "));
	return merged;
}
