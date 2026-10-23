import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { type Edge, type FileFacts, type Reference, realOf } from "./facts/facts.ts";
import type { Scope } from "./scope.ts";
import type { Surface } from "./surface.ts";
import type { Pkg } from "./workspace.ts";

/** The edges by which a file uses a package (a resolve uses none), each with its package and subpath. */
function packagesUsed(facts: FileFacts) {
	return facts.edges.flatMap((edge) =>
		edge.form !== "resolve" && edge.target.kind === "package"
			? [{ edge, name: edge.target.name, subpath: edge.target.subpath }]
			: [],
	);
}

/** Whether an edge loads its module yet binds types alone: `import { type T }` under verbatimModuleSyntax. */
const typesAloneLoaded = (edge: Edge) =>
	edge.loads && edge.bindings.length > 0 && edge.bindings.every((b) => b.typeOnly);

/** The values a file takes from the module `from` by its top-level imports and re-exports (none inside a declared module): `default`, a name, or `*`. */
export function valuesTaken(facts: FileFacts, from: string): string[] {
	return facts.edges
		.filter((e) => (e.form === "import" || e.form === "export-from") && e.specifier.text === from)
		.filter((e) => ts.isSourceFile(e.node.parent))
		.flatMap((e) => e.bindings.filter((b) => !b.typeOnly))
		.map((b) => (b.form === "named" ? b.imported : b.form === "default" ? "default" : "*"));
}

/** The local name a reference's import binding was declared under. */
function bindingNameOf(r: Reference): ts.Identifier | undefined {
	const b = r.binding;
	if (b?.kind !== "imported") return undefined;
	return b.edge.bindings.find((x) => x.local?.text === r.node.text)?.local;
}

/** The names imported by name from `from` that a `keyof typeof` of the file keys by. */
function keyedBy(facts: FileFacts, from: string): string[] {
	return facts.references
		.filter((r) => {
			const b = r.binding;
			const q = r.node.parent;
			return (
				r.role === "type-query" &&
				b?.kind === "imported" &&
				b.edge.form === "import" &&
				b.edge.specifier.text === from &&
				ts.isSourceFile(b.edge.node.parent) &&
				// A name imported by name, the default too, never a default clause or a namespace.
				b.edge.bindings.some((x) => x.form === "named" && x.local === bindingNameOf(r)) &&
				ts.isTypeQueryNode(q) &&
				ts.isTypeOperatorNode(q.parent) &&
				q.parent.operator === ts.SyntaxKind.KeyOfKeyword
			);
		})
		.map((r) => r.node.text);
}

/** G3, G4, G8: what one source file of a package may import. */
export function fileImportRules(s: Scope, p: Pkg, file: string) {
	const { byName, report } = s;
	const runtimeDeps = new Set(
		Object.keys({ ...p.manifest.dependencies, ...p.manifest.peerDependencies }),
	);
	const exportsModule = p.manifest.exports?.["./module"] !== undefined;
	if (s.isTest(file)) return;
	const where = `${p.name}/${file}`;
	for (const { edge, name, subpath } of packagesUsed(s.factsOf(p, file))) {
		const specifier = edge.specifier.text ?? "";
		if (exportsModule && byName.has(name) && subpath === "module") {
			report("G3 only assembly uses composition definitions", where, specifier);
		}
		if (byName.has(name) && subpath === "testing") {
			report("G4 contract tests are used only from tests", where, specifier);
		}
		if (edge.loads && !runtimeDeps.has(name)) {
			const hint = typesAloneLoaded(edge)
				? " (it still loads the module: import type { … } binds types alone)"
				: "";
			report("G8 runtime dependencies as declared", where, `${specifier}${hint}`);
		}
	}
}

/** G1 */
export function cycles(s: Scope) {
	const state = new Map<string, "open" | "done">();
	const visit = (name: string, path: string[]) => {
		if (state.get(name) === "open") {
			s.report("G1 no cycles", name, [...path, name].join(" → "));
			return;
		}
		if (state.get(name) === "done") return;
		state.set(name, "open");
		const p = s.byName.get(name);
		if (p) for (const dep of s.workspaceDeps(p, true)) visit(dep, [...path, name]);
		state.set(name, "done");
	};
	for (const p of s.packages) visit(p.name, []);
}

/** G2, G10, G14, G16: what a package may depend on. */
export function dependencyRules(s: Scope, p: Pkg) {
	const { budget, byName, kindOf, level, report, workspaceDeps } = s;
	// The bottom level (common, protocol) is what every kind may build on: it builds on nothing.
	if (level(p) === 0) {
		for (const dep of workspaceDeps(p, true)) {
			report("G2 the bottom level depends on nothing in the workspace", p.name, dep);
		}
	}
	if (level(p) < 0) report("G10 kind direction", p.name, "no kind, or an unknown kind");
	const runtime = new Set(workspaceDeps(p, false));
	for (const dep of workspaceDeps(p, true)) {
		const target = byName.get(dep) as Pkg;
		// Tests assemble, so a test may reach up to wiring, and to no other higher kind.
		const testUp = !runtime.has(dep) && kindOf(target) === budget.wiringKind;
		if (level(p) >= 0 && level(target) > level(p) && !testUp) {
			report("G10 kind direction", p.name, `a lower kind depends on a higher one: ${dep}`);
		}
	}
	// G14: a check package other check packages build on stays free of the product's modules.
	const isCheck = (q: Pkg) => kindOf(q) === budget.verificationKind;
	const builtOn = s.packages.some(
		(q) => q !== p && isCheck(q) && workspaceDeps(q, true).includes(p.name),
	);
	if (isCheck(p) && builtOn) {
		for (const dep of workspaceDeps(p, true)) {
			if (budget.productKinds.includes(kindOf(byName.get(dep) as Pkg))) {
				report("G14 a verification base depends on no product module", p.name, dep);
			}
		}
	}
	// G16: a feature never depends on a capability, nor on what declares forWiring; its tests may use the stand-in.
	const g16 = "G16 a feature depends on no capability, nor on what declares forWiring";
	if (p.manifest.forWiring !== undefined && p.manifest.forWiring !== true) {
		report(g16, p.name, "forWiring is true only");
	}
	if (budget.capabilityBlind.includes(kindOf(p))) {
		for (const dep of workspaceDeps(p, true)) {
			const target = byName.get(dep) as Pkg;
			if (kindOf(target) !== budget.capabilityKind && target.manifest.forWiring !== true) continue;
			const beyondStandIn = s
				.sources(p)
				.some((file) =>
					packagesUsed(s.factsOf(p, file)).some((u) => u.name === dep && u.subpath !== "testing"),
				);
			if (runtime.has(dep) || beyondStandIn) report(g16, p.name, dep);
		}
	}
}

/** G28: a dependency named as helpers lends functions and types, never a contract or an extension point. */
export function helperRules(s: Scope, p: Pkg, surfaces: ReadonlyMap<string, Surface>) {
	const helpers = Array.isArray(p.manifest.helpers) ? p.manifest.helpers : [];
	for (const file of s.sources(p).filter((f) => !s.isTest(f))) {
		for (const helper of helpers) {
			const tokens = surfaces.get(helper)?.tokens ?? new Set<string>();
			for (const name of valuesTaken(s.factsOf(p, file), helper)) {
				if (tokens.has(name) || (name === "*" && tokens.size > 0)) {
					s.report(
						"G28 a helpers dependency lends no contract",
						`${p.name}/${file}`,
						`${name} (${helper})`,
					);
				}
			}
		}
	}
}

/** G29: a test composing every module a feature bridge joins, and a module contributing to its points, composes the bridge. */
export function bridgeRules(s: Scope, surfaces: ReadonlyMap<string, Surface>) {
	const rule =
		"G29 a test composing a bridge's modules and a module contributing to it composes the bridge";
	// A feature bridge's points collect what decides answers; a foundation bridge's, operational counts.
	const bridges = s.packages.filter(
		(p) => Array.isArray(p.manifest.joins) && s.kindOf(p) === s.budget.featureKind,
	);
	const text = (path: string) => readFileSync(path, "utf8");
	// A package contributes to a bridge when its shipped code takes one of the bridge's points.
	const contributes = new Map<string, Pkg[]>();
	for (const p of s.packages) {
		const shipped = s.sources(p).filter((file) => !s.isTest(file));
		const takes = (b: Pkg) => {
			const points = surfaces.get(b.name)?.points ?? new Set<string>();
			return shipped.some((file) => {
				const path = join(p.dir, file);
				if (!text(path).includes(`"${b.name}"`)) return false;
				return valuesTaken(s.factsOf(p, file), b.name).some((name) => points.has(name));
			});
		};
		contributes.set(
			p.name,
			bridges.filter((b) => b !== p && takes(b)),
		);
	}
	const ownerOf = ({ manifest: { replaces, adapts } }: Pkg) =>
		typeof replaces === "string" ? replaces : typeof adapts === "string" ? adapts : undefined;
	for (const p of s.packages) {
		const own = p.manifest.exports?.["./module"];
		for (const file of s.sources(p).filter((f) => s.isTest(f))) {
			const composed = new Set<string>();
			const compose = (name: string) => {
				composed.add(name);
				const q = s.byName.get(name);
				const owner = q && ownerOf(q);
				if (owner) composed.add(owner);
			};
			const facts = s.factsOf(p, file);
			const ownModule = own && realOf(join(p.dir, own));
			// Loading the module composes it; resolving its path or importing its type does not.
			const ownTarget = (e: Edge) =>
				e.loads && e.target.kind === "file" && e.target.path === ownModule;
			if (ownModule && facts.edges.some(ownTarget)) compose(p.name);
			for (const { edge, name, subpath } of packagesUsed(facts).filter((u) => u.edge.loads)) {
				if (!s.byName.has(name)) continue;
				if (subpath === "module") compose(name);
				// A stand-in is a value a package's `./testing` names `…StandIn`.
				const standIn = (value: string) => value.endsWith("StandIn");
				const specifier = edge.specifier.text ?? "";
				if (subpath === "testing" && valuesTaken(facts, specifier).some(standIn)) compose(name);
			}
			for (const name of composed) {
				for (const b of contributes.get(name) ?? []) {
					const joins = b.manifest.joins as readonly unknown[];
					const all = joins.every((j) => typeof j === "string" && composed.has(j));
					if (all && !composed.has(b.name))
						s.report(rule, `${p.name}/${file}`, `${b.name} (${name})`);
				}
			}
		}
	}
}

/** G22, G24: which packages wire a feature's store interface, and how. */
export function wiringRules(s: Scope) {
	const { kindOf, report } = s;
	const g22 = "G22 only wiring wires, and a feature that declares storeWiring has one";
	const isWiring = (p: Pkg) => kindOf(p) === s.budget.wiringKind;
	const wired = new Set(s.packages.filter(isWiring).map((p) => p.manifest.wires));
	for (const p of s.packages) {
		if (p.manifest.wires !== undefined && !isWiring(p))
			report(g22, p.name, `kind ${kindOf(p) || "none"}`);
		if (p.manifest.storeWiring && !wired.has(p.name)) report(g22, p.name, "no package wires it");
	}
	// G24: a wiring keys its guarantees by the needs its feature declares, so the feature declares them.
	for (const w of s.packages.filter(isWiring)) {
		const feature = w.manifest.wires;
		if (feature === undefined) continue;
		const keyed = s
			.sources(w)
			.filter((file) => !s.isTest(file))
			.some((file) => keyedBy(s.factsOf(w, file), feature).length > 0);
		if (!keyed) {
			report(
				"G24 a wired feature declares its store's needs",
				feature,
				`${w.name} keys no guarantee by them`,
			);
		}
	}
}

/** G25: an adapter serves one axis of a workspace owner, an axis has one default, and optIn is a feature's. */
export function axisRules(s: Scope) {
	const { kindOf, report } = s;
	const g25 = "G25 an adapter serves one axis, with one default, and only a feature opts in";
	const axes = new Map<string, Pkg[]>();
	for (const p of s.packages) {
		const { replaces, adapts, joins } = p.manifest;
		const isAdapter = kindOf(p) === s.budget.adapterKind;
		if (isAdapter && replaces !== undefined && adapts !== undefined) {
			report(g25, p.name, "declares replaces and adapts");
		} else if (isAdapter && replaces === undefined && adapts === undefined) {
			report(g25, p.name, "declares neither replaces nor adapts");
		} else if (isAdapter) {
			const owner = String(replaces ?? adapts);
			if (!s.byName.has(owner)) report(g25, p.name, `names no workspace package: ${owner}`);
			else axes.set(owner, [...(axes.get(owner) ?? []), p]);
			// Wording comes with its axis as the default, so it never also joins its owner as a bridge.
			const wording = s
				.sources(p)
				.some(
					(file) =>
						!s.isTest(file) && readFileSync(join(p.dir, file), "utf8").includes("mailTemplates"),
				);
			if (wording && Array.isArray(joins) && joins.includes(owner)) {
				report(g25, p.name, "joins the owner it adapts");
			}
		}
		const flag = (key: "default" | "optIn", kind: string) => {
			const value = p.manifest[key];
			if (value === undefined) return;
			if (kindOf(p) !== kind) report(g25, p.name, `${key} on kind ${kindOf(p) || "none"}`);
			else if (value !== true) report(g25, p.name, `${key} is not true`);
		};
		flag("default", s.budget.adapterKind);
		flag("optIn", s.budget.featureKind);
	}
	for (const [owner, adapters] of axes) {
		const defaults = adapters.filter((p) => p.manifest.default === true).length;
		if (defaults > 1) report(g25, owner, `${defaults} defaults among its adapters`);
		if (adapters.length > 1 && defaults === 0) {
			report(g25, owner, `no default among its ${adapters.length} adapters`);
		}
	}
}
