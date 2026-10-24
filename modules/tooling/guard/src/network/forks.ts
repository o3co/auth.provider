/** The one starter a package's `forks` names, and the form it must start its helper in. */
import { lstatSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import type { Edge, EdgeBinding, FileFacts } from "@mod/guard-imports";
import ts from "typescript";

/** What a helper may reach: names resolved, nothing else. */
export const helperReach = "node:dns/promises lookup";
const envKeys = new Set(["UV_THREADPOOL_SIZE", "LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES"]);
const stdio = ["ignore", "ignore", "inherit", "ipc"];
const optionKeys = ["execPath", "execArgv", "env", "stdio", "serialization"];

/** A manifest's `forks`, starter to helper; undefined where it is no map of file to file. */
export function forksOf(declared: unknown): Map<string, string> | undefined {
	if (declared === undefined) return new Map();
	if (typeof declared !== "object" || declared === null || Array.isArray(declared))
		return undefined;
	const entries = Object.entries(declared);
	return entries.every(([, to]) => typeof to === "string")
		? new Map(entries as [string, string][])
		: undefined;
}

/** Whether a callee loads a module: `import`, or `require` however parenthesized. */
const isLoading = (callee: ts.Expression) => {
	let at = callee;
	while (ts.isParenthesizedExpression(at)) at = at.expression;
	return at.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(at) && at.text === "require");
};

/** `node:child_process` under either of its names. */
const childProcess = new Set(["child_process", "node:child_process"]);

/** A module loaded at run time: a dynamic import or a loader's call, by any name the facts read. */
const loadedAtRunTime = (e: Edge) => e.form === "dynamic-import" || e.form === "require";

/** Whether a file loads `node:child_process` at run time, or a module whose name is known at run time alone. */
function loadsChildProcessAtRunTime(facts: FileFacts): boolean {
	const named = (e: Edge) => e.specifier.text === undefined || childProcess.has(e.specifier.text);
	if (facts.edges.some((e) => loadedAtRunTime(e) && named(e))) return true;
	const file = facts.file;
	let found = false;
	const visit = (node: ts.Node): void => {
		if (ts.isCallExpression(node) && isLoading(node.expression)) {
			const [named] = node.arguments;
			if (!named || !ts.isStringLiteralLike(named) || childProcess.has(named.text)) found = true;
		}
		if (!found) ts.forEachChild(node, visit);
	};
	visit(file);
	return found;
}

/** Whether a file imports, re-exports or `import = require`s `node:child_process`, under either name, but by the one import of `fork`. */
function reachesChildProcessOtherwise(facts: FileFacts, fork: Edge | undefined) {
	const statically = new Set(["import", "export-from", "import-equals"]);
	return facts.edges.some(
		(e) =>
			statically.has(e.form) &&
			e.specifier.text !== undefined &&
			childProcess.has(e.specifier.text) &&
			e !== fork,
	);
}

/** Each `import()` and `require(…)` call in a file, by any name the facts read as a loader too: a module loaded otherwise than by an import. */
function loadsAtRunTime(facts: FileFacts): boolean {
	if (facts.edges.some(loadedAtRunTime)) return true;
	const file = facts.file;
	let found = false;
	const visit = (node: ts.Node): void => {
		if (ts.isCallExpression(node) && isLoading(node.expression)) {
			found = true;
		}
		if (!found) ts.forEachChild(node, visit);
	};
	visit(file);
	return found;
}

/** The binding a file imports `name` under from `module` by name, and whether that is all it imports from there. */
function namedImport(facts: FileFacts, module: string, name: string) {
	const from = facts.edges.filter((e) => e.form === "import" && e.specifier.text === module);
	const bindings = from.flatMap((e) => e.bindings);
	const only = bindings[0];
	const alone =
		from.length === 1 &&
		bindings.length === 1 &&
		only?.form === "named" &&
		only.imported === name &&
		!only.typeOnly;
	const binding = bindings.find((b) => b.form === "named" && b.imported === name && !b.typeOnly);
	const edge = from.find((e) => e.bindings.includes(binding as EdgeBinding));
	return { local: binding?.local, alone, edge: binding ? edge : undefined };
}

/** Each place a value an import binds is read: a name shadowing it is another; a type, a type query or a type-only export reads nothing at run time. */
function readsOf(facts: FileFacts, edge: Edge, name: string): ts.Identifier[] {
	return facts.references
		.filter(
			(r) =>
				r.role === "value" &&
				r.binding?.kind === "imported" &&
				r.binding.edge === edge &&
				r.binding.name === name,
		)
		.map((r) => r.node);
}

/** Whether a name is unbound in the file's lexical scope, as the facts read it. */
const isUnbound = (facts: FileFacts, name: ts.Identifier) =>
	facts.references.some((r) => r.node === name && r.binding?.kind === "unbound");

const isLiteral = (node: ts.Node | undefined, text?: string): node is ts.StringLiteral =>
	node !== undefined && ts.isStringLiteral(node) && (text === undefined || node.text === text);

/** `import.meta.dirname`, as written. */
const isDirname = (node: ts.Node | undefined) =>
	node !== undefined &&
	ts.isPropertyAccessExpression(node) &&
	ts.isMetaProperty(node.expression) &&
	node.expression.keywordToken === ts.SyntaxKind.ImportKeyword &&
	node.name.text === "dirname";

/** Whether an options literal is the launch form: these keys alone, each as written below. */
function isLaunchForm(
	options: ts.Expression | undefined,
	isProcess: (name: ts.Identifier) => boolean,
): boolean {
	if (!options || !ts.isObjectLiteralExpression(options)) return false;
	const props = new Map<string, ts.Expression>();
	for (const p of options.properties) {
		if (!ts.isPropertyAssignment(p) || !ts.isIdentifier(p.name)) return false;
		props.set(p.name.text, p.initializer);
	}
	if (props.size !== optionKeys.length || !optionKeys.every((k) => props.has(k))) return false;
	const execPath = props.get("execPath");
	const execArgv = props.get("execArgv");
	const env = props.get("env");
	const io = props.get("stdio");
	const execPathOk =
		execPath !== undefined &&
		ts.isPropertyAccessExpression(execPath) &&
		ts.isIdentifier(execPath.expression) &&
		execPath.expression.text === "process" &&
		isProcess(execPath.expression) &&
		execPath.name.text === "execPath";
	const argvOk =
		execArgv !== undefined &&
		ts.isArrayLiteralExpression(execArgv) &&
		// Exactly the heap limit: none would leave the helper at Node's own.
		execArgv.elements.length === 1 &&
		execArgv.elements.every((e) => isLiteral(e) && /^--max-old-space-size=\d+$/.test(e.text));
	const envOk =
		env !== undefined &&
		ts.isObjectLiteralExpression(env) &&
		env.properties.every(
			(p) =>
				ts.isPropertyAssignment(p) &&
				(ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) &&
				envKeys.has(p.name.text),
		);
	const stdioOk =
		io !== undefined &&
		ts.isArrayLiteralExpression(io) &&
		io.elements.length === stdio.length &&
		io.elements.every((e, i) => isLiteral(e, stdio[i]));
	return execPathOk && argvOk && envOk && stdioOk && isLiteral(props.get("serialization"), "json");
}

/**
 * Why the starter does not start its helper as written: `fork` imported by name alone, read in one
 * call, given `join(import.meta.dirname, "<helper>")`, a list, and the launch form; the helper a
 * plain file beside it. Nothing where it does.
 */
export function launchRefusal(
	facts: FileFacts,
	dir: string,
	starter: string,
	helper: string,
): string | undefined {
	// Node runs a link as the file it links to, beside another helper than the one checked here.
	if (lstatSync(join(dir, starter)).isSymbolicLink()) return "is a plain file, never a link";
	const fork = namedImport(facts, "node:child_process", "fork");
	if (
		!fork.alone ||
		fork.local === undefined ||
		fork.edge === undefined ||
		reachesChildProcessOtherwise(facts, fork.edge)
	)
		return "imports from node:child_process fork by its name alone";
	if (loadsChildProcessAtRunTime(facts)) return "loads node:child_process by the import alone";
	const reads = readsOf(facts, fork.edge, "fork");
	const call = reads[0]?.parent;
	if (reads.length !== 1 || !call || !ts.isCallExpression(call) || call.expression !== reads[0])
		return "uses fork in one call alone";
	let plain = false;
	try {
		plain = lstatSync(join(dir, helper)).isFile();
	} catch {}
	if (dirname(helper) !== dirname(starter) || !helper.endsWith(".mjs") || !plain)
		return "forks names a helper beside it, a plain .mjs file";
	const joinImport = namedImport(facts, "node:path", "join").edge;
	const joins = joinImport ? readsOf(facts, joinImport, "join") : [];
	const [named, args, options, ...more] = call.arguments;
	const namedOk =
		named !== undefined &&
		ts.isCallExpression(named) &&
		ts.isIdentifier(named.expression) &&
		joins.includes(named.expression) &&
		named.arguments.length === 2 &&
		isDirname(named.arguments[0]) &&
		isLiteral(named.arguments[1], basename(helper));
	if (!namedOk) return `names the helper as join(import.meta.dirname, "${basename(helper)}")`;
	const isProcess = (name: ts.Identifier) => isUnbound(facts, name);
	if (
		more.length > 0 ||
		!args ||
		!ts.isArrayLiteralExpression(args) ||
		!isLaunchForm(options, isProcess)
	)
		return "starts it in the launch form";
	return undefined;
}

/** Whether a declared helper is a plain `.mjs` file, never a directory, a card or a link. */
export function isPlainHelper(path: string): boolean {
	try {
		return path.endsWith(".mjs") && lstatSync(path).isFile();
	} catch {
		return false;
	}
}

/** Whether a helper imports node:dns/promises' lookup and nothing else, statically or at run time. */
export function importsLookupAlone(facts: FileFacts, reaches: readonly string[]): boolean {
	const imports = facts.file.statements.filter(ts.isImportDeclaration);
	const exportsFrom = facts.file.statements.some((st) => ts.isExportDeclaration(st));
	return (
		imports.length === 1 &&
		!exportsFrom &&
		!loadsAtRunTime(facts) &&
		namedImport(facts, "node:dns/promises", "lookup").alone &&
		reaches.every((reach) => reach === helperReach)
	);
}
