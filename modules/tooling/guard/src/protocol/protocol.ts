import { realpathSync } from "node:fs";
import { join } from "node:path";
import type { Edge, FileFacts, Pkg } from "@mod/guard-imports";
import ts from "typescript";
import type { Scope } from "../units.ts";

/** What a protocol may import at run time beside files, whose place G34 holds. */
const importable = new Set(["zod"]);

/** The globals a protocol may reach: values and constructors that hold no behaviour of the host. */
const reachable = new Set([
	"Object",
	"Array",
	"String",
	"Number",
	"Boolean",
	"JSON",
	"Symbol",
	"RegExp",
	"Error",
	"TypeError",
	"RangeError",
	"undefined",
	"NaN",
	"Infinity",
]);

/** Whether an edge that loads its module takes what a protocol may: zod, or a file. */
const allowed = ({ target }: Edge) =>
	target.kind === "file" ||
	(target.kind === "unresolved" && target.path !== undefined) ||
	(target.kind === "package" && importable.has(target.name) && target.subpath === "");

/** What a file's shipped code reaches beyond its contract, each as G33 says it, in the file's order. */
function reachedIn(facts: FileFacts, tests: ReadonlySet<string>): string[] {
	const found: [number, string][] = [];
	for (const edge of facts.edges.filter((e) => e.loads)) {
		const at = edge.node.getStart();
		if (edge.form === "dynamic-import") found.push([at, "loads a module at run time: import()"]);
		// A test file is not read here, so what it runs would ship unread.
		else if (edge.target.kind === "file" && tests.has(edge.target.path)) {
			found.push([at, `loads a test file: ${edge.specifier.text}`]);
		}
		// A loader is `require`, a global refused below, or made by what it may not import.
		else if (edge.form !== "require" && !allowed(edge)) {
			found.push([
				at,
				`imports ${edge.specifier.text}: a protocol imports zod and its own files alone`,
			]);
		}
	}
	for (const r of facts.references) {
		if (r.role === "value" && r.binding?.kind === "unbound" && !reachable.has(r.node.text)) {
			found.push([r.node.getStart(), `reaches the global ${r.node.text}`]);
		}
	}
	// facts hold no meta property: read here, and moved into facts when a second rule reads one.
	const visit = (node: ts.Node): void => {
		if (ts.isMetaProperty(node) && node.keywordToken === ts.SyntaxKind.ImportKeyword) {
			found.push([node.getStart(), "reads import.meta"]);
		}
		ts.forEachChild(node, visit);
	};
	visit(facts.file);
	return found.sort(([a], [b]) => a - b).map(([, what]) => what);
}

/** Each top-level statement that keeps state or runs as the file loads, by what it is. */
function loadedState(file: ts.SourceFile): string[] {
	return file.statements.flatMap((statement) => {
		if (ts.isVariableStatement(statement)) {
			const flags = statement.declarationList.flags;
			if (flags & ts.NodeFlags.Const) return [];
			return [flags & ts.NodeFlags.Let ? "let" : "var"];
		}
		if (ts.isClassDeclaration(statement)) return ["class"];
		const declares =
			ts.isImportDeclaration(statement) ||
			// An alias of a type alone runs nothing; one of a value loads its module as the file loads.
			(ts.isImportEqualsDeclaration(statement) && statement.isTypeOnly) ||
			ts.isExportDeclaration(statement) ||
			// A default export: what it exports is read as any value is.
			(ts.isExportAssignment(statement) && !statement.isExportEquals) ||
			ts.isInterfaceDeclaration(statement) ||
			ts.isTypeAliasDeclaration(statement) ||
			ts.isFunctionDeclaration(statement) ||
			ts.isEmptyStatement(statement);
		return declares ? [] : ["a statement"];
	});
}

/**
 * G33: a protocol package holds a wire's contract alone. It exports its contract alone and declares
 * no network word nor forks. Its shipped code imports at run time zod and files alone, loads no
 * module at run time, reaches no global beyond those holding no behaviour of the host, and keeps no
 * state nor runs anything as a file loads.
 */
export function protocolRules(s: Scope, p: Pkg) {
	if (s.kindOf(p) !== s.budget.protocolKind) return;
	const rule = "G33 a protocol holds a wire's contract alone";
	for (const key of Object.keys(p.manifest.exports ?? {})) {
		if (key !== ".")
			s.report(rule, p.name, `exports ${key}: a protocol exports its contract alone`);
	}
	for (const field of ["network", "forks"] as const) {
		if (p.manifest[field] !== undefined) {
			s.report(rule, p.name, `declares ${field}: a protocol reaches nothing`);
		}
	}
	const tests = new Set(
		s
			.sources(p)
			.filter((f) => s.isTest(f))
			.map((f) => realpathSync(join(p.dir, f))),
	);
	for (const file of s.sources(p).filter((f) => !s.isTest(f))) {
		const where = `${p.name}/${file}`;
		const facts = s.factsOf(p, file);
		for (const what of reachedIn(facts, tests)) s.report(rule, where, what);
		for (const what of loadedState(facts.file)) {
			s.report(rule, where, `holds state or runs as it loads: ${what}`);
		}
	}
}
