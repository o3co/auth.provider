/** A change record's machine rows: what two states of the workspace differ in, as a reviewer reads it. */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type Pkg, surfacesOf } from "@mod/guard-imports";
import { type Budget, measures } from "../contract.ts";
import { unitsOf } from "../units.ts";

/** One state of the workspace, as the record compares it. */
export interface Reading {
	readonly commit: string;
	readonly tree: string;
	/** Each unit (a package, or an internal module apart from it), by where: its files, relative to the package, and their content's hash. */
	readonly files: ReadonlyMap<string, ReadonlyMap<string, string>>;
	/** Each package's exports, by name: their structure, as `guard-imports`' surface writes it. */
	readonly signatures: ReadonlyMap<string, ReadonlyMap<string, string>>;
	/** `<from> -> <to> (run time|tests)`, as the manifests name workspace packages. */
	readonly edges: ReadonlySet<string>;
	/** `<where>\t<what>` → the budget's measure and its limit. */
	readonly measures: ReadonlyMap<string, { readonly value: number; readonly limit?: number }>;
}

export function readingOf(
	packages: readonly Pkg[],
	budget: Budget,
	at: { readonly commit: string; readonly tree: string },
): Reading {
	const files = new Map<string, Map<string, string>>();
	for (const p of packages) {
		const { unitOf, whereOf } = unitsOf(p);
		for (const file of p.files) {
			const where = whereOf(unitOf(file));
			const hash = createHash("sha256")
				.update(readFileSync(join(p.dir, file)))
				.digest("hex");
			files.set(where, (files.get(where) ?? new Map()).set(file, hash));
		}
	}
	const names = new Set(packages.map((p) => p.name));
	const edges = new Set(
		packages.flatMap((p) => {
			const { dependencies = {}, peerDependencies = {}, devDependencies = {} } = p.manifest;
			const to = (deps: Record<string, string>, as: string) =>
				Object.keys(deps)
					.filter((d) => names.has(d))
					.map((d) => `${p.name} -> ${d} (${as})`);
			return [
				...to({ ...dependencies, ...peerDependencies }, "run time"),
				...to(devDependencies, "tests"),
			];
		}),
	);
	// Each package's surface builds a program of its own: read once, for the signatures and the measures.
	const surfaces = surfacesOf(packages);
	const signatures = new Map([...surfaces].map(([name, surface]) => [name, surface.signatures]));
	const measured = new Map(
		measures(packages, budget, surfaces).map(({ where, what, value, limit }) => [
			`${where}\t${what}`,
			limit === undefined ? { value } : { value, limit },
		]),
	);
	return { ...at, files, signatures, edges, measures: measured };
}

export type ContractChange =
	| { readonly package: string; readonly name: string; readonly kind: "added" | "removed" }
	| {
			readonly package: string;
			readonly name: string;
			readonly kind: "renamed" | "moved";
			readonly to: string;
	  }
	| {
			readonly package: string;
			readonly name: string;
			readonly kind: "changed";
			readonly from: string;
			readonly to: string;
	  };

export interface MeasureChange {
	readonly where: string;
	readonly what: string;
	readonly from?: number;
	readonly to?: number;
	readonly limit?: number;
}

const sorted = (values: Iterable<string>) => [...values].sort();
const lastPart = (where: string) => where.split("/").at(-1);
const sameFiles = (a?: ReadonlyMap<string, string>, b?: ReadonlyMap<string, string>) =>
	a?.size === b?.size && [...(a ?? [])].every(([file, hash]) => b?.get(file) === hash);

/** The units added, removed, moved (the one gone and the one come with the same last part) and changed. */
function unitChanges(base: Reading, head: Reading) {
	const gone = sorted([...base.files.keys()].filter((w) => !head.files.has(w)));
	const come = sorted([...head.files.keys()].filter((w) => !base.files.has(w)));
	// A move only where the last part names one unit gone and one come: an ambiguous match stays the removals and the additions.
	const moved = gone.flatMap((from) => {
		const to = come.filter((w) => lastPart(w) === lastPart(from));
		const alike = gone.filter((w) => lastPart(w) === lastPart(from));
		return to.length === 1 && alike.length === 1 && to[0] !== undefined
			? [[from, to[0]] as [string, string]]
			: [];
	});
	const changed = sorted(
		[...base.files.keys()].filter(
			(w) => head.files.has(w) && !sameFiles(base.files.get(w), head.files.get(w)),
		),
	);
	return {
		added: come.filter((w) => !moved.some(([, to]) => to === w)),
		removed: gone.filter((w) => !moved.some(([from]) => from === w)),
		moved,
		changed,
	};
}

/** A signature with its export's own name masked, wherever it names it: what a rename keeps. */
const shapeOf = (name: string, signature: string) =>
	signature.replace(new RegExp(`(?<![\\w$])${name.replace(/[$]/g, "\\$")}(?![\\w$])`, "g"), "·");

/** Each export added, removed, changed, renamed (another name, the same signature, in its package) or moved (the same name and signature, in another). */
function contractChanges(base: Reading, head: Reading): ContractChange[] {
	const of = (r: Reading, p: string) => r.signatures.get(p) ?? new Map<string, string>();
	const packages = sorted(new Set([...base.signatures.keys(), ...head.signatures.keys()]));
	const taken = new Set<string>();
	const changes: ContractChange[] = [];
	for (const p of packages) {
		const [before, after] = [of(base, p), of(head, p)];
		for (const [name, signature] of before) {
			const now = after.get(name);
			if (now === signature) continue;
			if (now !== undefined) {
				changes.push({ package: p, name, kind: "changed", from: signature, to: now });
				continue;
			}
			const renamed = [...after].find(
				([other, s]) =>
					shapeOf(other, s) === shapeOf(name, signature) &&
					!before.has(other) &&
					!taken.has(`${p}\t${other}`),
			);
			const moved = packages.find(
				(q) => q !== p && of(head, q).get(name) === signature && !of(base, q).has(name),
			);
			if (renamed) {
				taken.add(`${p}\t${renamed[0]}`);
				changes.push({ package: p, name, kind: "renamed", to: renamed[0] });
			} else if (moved) {
				taken.add(`${moved}\t${name}`);
				changes.push({ package: p, name, kind: "moved", to: moved });
			} else changes.push({ package: p, name, kind: "removed" });
		}
	}
	for (const p of packages) {
		for (const name of of(head, p).keys()) {
			if (!of(base, p).has(name) && !taken.has(`${p}\t${name}`))
				changes.push({ package: p, name, kind: "added" });
		}
	}
	return changes.sort((a, b) => a.package.localeCompare(b.package) || a.name.localeCompare(b.name));
}

/** Each measure whose value differs, or that one state alone has. */
function measureChanges(base: Reading, head: Reading): MeasureChange[] {
	return sorted(new Set([...base.measures.keys(), ...head.measures.keys()])).flatMap((key) => {
		const [before, after] = [base.measures.get(key), head.measures.get(key)];
		if (before?.value === after?.value) return [];
		const [where = "", what = ""] = key.split("\t");
		const limit = after?.limit ?? before?.limit;
		return [
			{
				where,
				what,
				...(before ? { from: before.value } : {}),
				...(after ? { to: after.value } : {}),
				...(limit === undefined ? {} : { limit }),
			},
		];
	});
}

export function changesOf(base: Reading, head: Reading) {
	return {
		units: unitChanges(base, head),
		contract: contractChanges(base, head),
		edges: {
			added: sorted([...head.edges].filter((e) => !base.edges.has(e))),
			removed: sorted([...base.edges].filter((e) => !head.edges.has(e))),
		},
		measures: measureChanges(base, head),
	};
}

/** Inline code, fenced so a backtick inside it holds. */
const code = (text: string) => (text.includes("`") ? `\`\` ${text} \`\`` : `\`${text}\``);
const listed = (lines: readonly string[]) =>
	lines.length === 0 ? "None.\n" : `${lines.join("\n")}\n`;

const contractLine = (c: ContractChange) => {
	const head = `- ${code(c.package)} ${code(c.name)}:`;
	if (c.kind === "changed")
		return `${head} changed\n  - before: ${code(c.from)}\n  - after: ${code(c.to)}`;
	if (c.kind === "renamed" || c.kind === "moved") return `${head} ${c.kind} to ${code(c.to)}`;
	return `${head} ${c.kind}`;
};

export function changeRecordOf(base: Reading, head: Reading): string {
	const { units, contract, edges, measures: moved } = changesOf(base, head);
	const rows = moved.map(
		(m) => `| ${code(m.where)} | ${m.what} | ${m.from ?? ""} | ${m.to ?? ""} | ${m.limit ?? ""} |`,
	);
	return [
		`# Change record: ${base.commit.slice(0, 9)} to ${head.commit.slice(0, 9)}`,
		"",
		"Written by `guard`'s `change-record` from the two commits alone; it keeps nothing.",
		"",
		"## Compared",
		"",
		"| | Commit | Tree |",
		"|---|---|---|",
		`| base | ${code(base.commit)} | ${code(base.tree)} |`,
		`| head | ${code(head.commit)} | ${code(head.tree)} |`,
		"",
		"## Modules touched",
		"",
		listed([
			...units.added.map((w) => `- Added: ${code(w)}`),
			...units.removed.map((w) => `- Removed: ${code(w)}`),
			...units.moved.map(([from, to]) => `- Moved: ${code(from)} to ${code(to)}`),
			...units.changed.map((w) => `- Changed: ${code(w)}`),
		]),
		"## Contract changes",
		"",
		"Each package's exports from its entry, compared by their structure.",
		"",
		listed(contract.map(contractLine)),
		"## Dependency edges",
		"",
		listed([
			...edges.added.map((e) => `- Added: ${code(e)}`),
			...edges.removed.map((e) => `- Removed: ${code(e)}`),
		]),
		"## Budget measures",
		"",
		"Each measure that moved; one the base or the head alone has is blank on the other side.",
		"",
		rows.length === 0
			? "None.\n"
			: ["| Unit | Measure | Base | Head | Limit |", "|---|---|---|---|---|", ...rows, ""].join(
					"\n",
				),
		"By hand: the owner's confirmation of each contract change, the reruns of the checks that hold the guarantees (with their runs), and whether a design review was needed, with its review.",
		"",
	].join("\n");
}
