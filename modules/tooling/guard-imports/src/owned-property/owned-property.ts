import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { budgetsAsTest, type Scope } from "../scope.ts";
import type { Pkg } from "../workspace.ts";
import { byNameReading, isTemplate, typedReading, writesIn } from "./writes/writes.ts";

const options: ts.CompilerOptions = {
	target: ts.ScriptTarget.ES2022,
	module: ts.ModuleKind.ESNext,
	moduleResolution: ts.ModuleResolutionKind.Bundler,
	allowImportingTsExtensions: true,
	noEmit: true,
	allowJs: true,
	strict: true,
	skipLibCheck: true,
	types: [],
};

/** Where shipped code writes the owned property: its file and line. */
interface Written {
	readonly pkg: Pkg;
	readonly file: string;
	readonly line: number;
}

/** What an owner holds to declaration: its package, and the type its contract exports with the property. */
export interface Owned {
	readonly owner: Pkg;
	readonly type: string;
	readonly property: string;
}

/**
 * Each write of the owned property in the shipped code of `packages`, as `writes` finds and judges it
 * by the type the owner's type gives that property, and in their templates by name; or why the owner's
 * type cannot be read.
 */
function writtenIn(
	s: Scope,
	{ owner, type, property: owned }: Owned,
	packages: readonly Pkg[],
): Written[] | string {
	const paths = Object.fromEntries(
		s.packages.flatMap((p) => {
			const entry = p.manifest.exports?.["."];
			return entry ? [[p.name, [join(p.dir, entry)]]] : [];
		}),
	);
	const entry = owner.manifest.exports?.["."];
	if (entry === undefined) return "exports no contract";
	const files = packages.flatMap((p) =>
		s
			.sources(p)
			.filter(
				(file) => (file.endsWith(".ts") || file.endsWith(".mjs")) && !budgetsAsTest(s, p, file),
			)
			.map((file) => ({ p, path: join(p.dir, file), file })),
	);
	const ownerEntry = join(owner.dir, entry);
	const program = ts.createProgram([ownerEntry, ...files.map((f) => f.path)], {
		...options,
		paths,
	});
	const checker = program.getTypeChecker();
	// The owner's type as its contract exports it, wherever it is declared.
	const contract = program.getSourceFile(ownerEntry);
	const module = contract && checker.getSymbolAtLocation(contract);
	const exported = module && checker.getExportsOfModule(module).find((e) => e.name === type);
	const declared =
		exported && exported.flags & ts.SymbolFlags.Alias
			? checker.getAliasedSymbol(exported)
			: exported;
	const property = declared && checker.getDeclaredTypeOfSymbol(declared).getProperty(owned);
	if (property === undefined) return `exports no ${type} with ${owned}`;
	const wanted = checker.getNonNullableType(checker.getTypeOfSymbol(property));
	const typed = typedReading(checker, wanted, owned);
	const written = files.flatMap(({ p, path, file }) => {
		const source = program.getSourceFile(path);
		return source ? writesIn(source, typed).map((line) => ({ pkg: p, file, line })) : [];
	});
	return [...written, ...templatedIn(s, owned, packages)];
}

/**
 * Each write of the owned property in the templates of `packages`, in every form a source's is
 * counted, by name alone: a template's imports are filled in when it is written out, so its values
 * have no type to read. A computed key or an element access counts unless it is a literal of another
 * name.
 */
function templatedIn(s: Scope, owned: string, packages: readonly Pkg[]): Written[] {
	const byName = byNameReading(owned);
	return packages.flatMap((p) =>
		p.files
			.filter((f) => isTemplate(f) && !budgetsAsTest(s, p, f))
			.flatMap((file) => {
				const text = readFileSync(join(p.dir, file), "utf8");
				const source = ts.createSourceFile(
					file,
					text,
					ts.ScriptTarget.ES2022,
					true,
					ts.ScriptKind.TS,
				);
				return writesIn(source, byName).map((line) => ({ pkg: p, file, line }));
			}),
	);
}

/** An owner's statement of what it holds to declaration, `{ type, property }`, or none where it is not one. */
const ownedOf = (value: unknown): { type: string; property: string } | undefined => {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	const { type, property } = value as Record<string, unknown>;
	return typeof type === "string" && typeof property === "string" && type !== "" && property !== ""
		? { type, property }
		: undefined;
};

/** What the workspace's manifests state of a property held to declaration, read once for every reader. */
export interface PropertyDeclarations {
	/** The packages stating, in `narrowerOwner`, the type and property they hold to declaration. */
	readonly owners: readonly Owned[];
	/** The packages whose `narrowerOwner` names no type and property. */
	readonly malformed: readonly Pkg[];
	/** The packages declaring, in `narrower`, the property they write, whatever its value. */
	readonly declaring: readonly Pkg[];
}

/** The owners' `narrowerOwner` and the writers' `narrower` in `packages`. */
export function propertyDeclarations(packages: readonly Pkg[]): PropertyDeclarations {
	const owners: Owned[] = [];
	const malformed: Pkg[] = [];
	const declaring: Pkg[] = [];
	for (const p of packages) {
		const stated = p.manifest.narrowerOwner;
		if (stated !== undefined) {
			const owned = ownedOf(stated);
			if (owned === undefined) malformed.push(p);
			else owners.push({ owner: p, ...owned });
		}
		if (p.manifest.narrower !== undefined) declaring.push(p);
	}
	return { owners, malformed, declaring };
}

/**
 * G32: shipped code writes the property an owner holds to declaration (the narrower's `internal`,
 * which reaches private addresses) only in the packages that declare it, `narrower` in their manifest
 * stating the property and their card stating that; each declaring package writes one. The owner
 * states the type and the property in its `narrowerOwner`.
 */
export function ownedPropertyRules(s: Scope) {
	const rule = "G32 an owned property is written only by the packages declaring it";
	const { owners, malformed, declaring } = propertyDeclarations(s.packages);
	for (const p of malformed) {
		s.report(rule, p.name, "narrowerOwner names no type and property it holds to declaration");
	}
	// The workspace's rules say how many owners there must be: none stating it leaves writes unheld.
	const required = s.budget.declaredProperties ?? 0;
	if (owners.length < required) {
		s.report(
			rule,
			"workspace",
			`${required} package(s) must state what they hold to declaration, ${owners.length} do`,
		);
	}
	const [owned, ...others] = owners;
	if (owned === undefined) {
		for (const p of declaring) {
			s.report(rule, p.name, `narrower: ${String(p.manifest.narrower)}, but no package owns it`);
		}
		return;
	}
	for (const other of others) {
		s.report(rule, owned.owner.name, `narrowerOwner: ${other.owner.name} states it owns it too`);
	}
	if (others.length > 0) return;
	const { property } = owned;
	const declared = new Set<string>();
	for (const p of declaring) {
		const value = p.manifest.narrower;
		if (value !== property) {
			s.report(
				rule,
				p.name,
				`narrower is ${JSON.stringify(value)}, not exactly ${JSON.stringify(property)}`,
			);
			continue;
		}
		declared.add(p.name);
		if (!(p.card ?? "").includes(`\`narrower\`: \`${property}\``)) {
			s.report(rule, p.name, `card states \`narrower\`: \`${property}\``);
		}
	}
	// The owner too: it states the property, and writes none.
	const written = writtenIn(s, owned, s.packages);
	if (typeof written === "string") {
		s.report(rule, owned.owner.name, `narrowerOwner, but it ${written}`);
		return;
	}
	for (const name of declared) {
		if (!written.some((w) => w.pkg.name === name)) {
			s.report(rule, name, `narrower: ${property}, but it writes none`);
		}
	}
	for (const w of written.filter((w) => !declared.has(w.pkg.name))) {
		s.report(rule, `${w.pkg.name}/${w.file}:${w.line}`, property);
	}
}
