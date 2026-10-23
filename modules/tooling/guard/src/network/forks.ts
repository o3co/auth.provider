/** The one starter a package's `forks` names, and the form it must start its helper in. */
import { lstatSync } from "node:fs";
import { basename, dirname, join } from "node:path";
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

/** The file alone, bound by the compiler: a name resolves to the declaration in scope where it is used. */
function bound(path: string) {
	const program = ts.createProgram([path], {
		noLib: true,
		noResolve: true,
		types: [],
		allowJs: true,
	});
	return { file: program.getSourceFile(path) as ts.SourceFile, checker: program.getTypeChecker() };
}

/** Whether a callee loads a module: `import`, or `require` however parenthesized. */
const isLoading = (callee: ts.Expression) => {
	let at = callee;
	while (ts.isParenthesizedExpression(at)) at = at.expression;
	return at.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(at) && at.text === "require");
};

/** `node:child_process` under either of its names. */
const childProcess = new Set(["child_process", "node:child_process"]);

/** Whether a file loads `node:child_process` at run time, or a module whose name is known at run time alone. */
function loadsChildProcessAtRunTime(file: ts.SourceFile): boolean {
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

/** Whether a file imports or re-exports from `node:child_process`, under either name, but by the one import of `fork`. */
function reachesChildProcessOtherwise(file: ts.SourceFile, fork: ts.ImportDeclaration | undefined) {
	return file.statements.some(
		(st) =>
			(ts.isImportDeclaration(st) || ts.isExportDeclaration(st)) &&
			st.moduleSpecifier !== undefined &&
			ts.isStringLiteral(st.moduleSpecifier) &&
			childProcess.has(st.moduleSpecifier.text) &&
			st !== fork,
	);
}

/** Each `import()` and `require(…)` call in a file: a module loaded otherwise than by an import. */
function loadsAtRunTime(file: ts.SourceFile): boolean {
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
function namedImport(file: ts.SourceFile, module: string, name: string) {
	const from = file.statements.filter(
		(st): st is ts.ImportDeclaration =>
			ts.isImportDeclaration(st) &&
			ts.isStringLiteral(st.moduleSpecifier) &&
			st.moduleSpecifier.text === module,
	);
	const elements = from.flatMap((st) => {
		const named = st.importClause?.namedBindings;
		return named && ts.isNamedImports(named) ? [...named.elements] : [];
	});
	const alone =
		from.length === 1 &&
		!from[0]?.importClause?.name &&
		!from[0]?.importClause?.isTypeOnly &&
		elements.length === 1 &&
		(elements[0]?.propertyName ?? elements[0]?.name)?.text === name &&
		!elements[0]?.isTypeOnly;
	const element = elements.find((e) => (e.propertyName ?? e.name).text === name && !e.isTypeOnly);
	return { local: element?.name, alone, declaration: from.length === 1 ? from[0] : undefined };
}

const isWithin = (node: ts.Node, outer: ts.Node) => node.pos >= outer.pos && node.end <= outer.end;

/**
 * Each place the binding an import made is read, by binding: a name shadowing it is another, and a
 * shorthand property or an export naming it is a read of it.
 */
function readsOf(
	file: ts.SourceFile,
	checker: ts.TypeChecker,
	binding: ts.Identifier,
): ts.Identifier[] {
	const symbol = checker.getSymbolAtLocation(binding);
	const resolved = (name: ts.Identifier) => {
		const parent = name.parent;
		if (ts.isShorthandPropertyAssignment(parent) && parent.name === name) {
			return checker.getShorthandAssignmentValueSymbol(parent);
		}
		if (ts.isExportSpecifier(parent) && (parent.propertyName ?? parent.name) === name) {
			return checker.getExportSpecifierLocalTargetSymbol(parent);
		}
		return checker.getSymbolAtLocation(name);
	};
	/** Read as a type alone, which is erased: in a type, or in an export of types only. */
	const typeOnly = (name: ts.Identifier) => {
		for (let at: ts.Node = name.parent; !ts.isSourceFile(at); at = at.parent) {
			// A class's extends is a value, run: only its type arguments are erased.
			if (
				ts.isExpressionWithTypeArguments(at) &&
				ts.isHeritageClause(at.parent) &&
				at.parent.token === ts.SyntaxKind.ExtendsKeyword &&
				ts.isClassLike(at.parent.parent)
			) {
				return !isWithin(name, at.expression);
			}
			if (ts.isTypeNode(at) || ts.isTypeQueryNode(at)) return true;
			if (ts.isExportSpecifier(at) && (at.isTypeOnly || at.parent.parent.isTypeOnly)) return true;
		}
		return false;
	};
	const found: ts.Identifier[] = [];
	const visit = (node: ts.Node): void => {
		if (ts.isImportDeclaration(node)) return;
		if (
			ts.isIdentifier(node) &&
			node.text === binding.text &&
			!typeOnly(node) &&
			resolved(node) === symbol
		) {
			found.push(node);
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return found;
}

/** Whether a name is the global of that name: nothing in the file declares it. */
const isGlobal = (checker: ts.TypeChecker, name: ts.Identifier, file: ts.SourceFile) =>
	!(checker.getSymbolAtLocation(name)?.declarations ?? []).some((d) => d.getSourceFile() === file);

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
export function launchRefusal(dir: string, starter: string, helper: string): string | undefined {
	// Node runs a link as the file it links to, beside another helper than the one checked here.
	if (lstatSync(join(dir, starter)).isSymbolicLink()) return "is a plain file, never a link";
	const { file, checker } = bound(join(dir, starter));
	const fork = namedImport(file, "node:child_process", "fork");
	if (
		!fork.alone ||
		fork.local === undefined ||
		reachesChildProcessOtherwise(file, fork.declaration)
	)
		return "imports from node:child_process fork by its name alone";
	if (loadsChildProcessAtRunTime(file)) return "loads node:child_process by the import alone";
	const reads = readsOf(file, checker, fork.local);
	const call = reads[0]?.parent;
	if (reads.length !== 1 || !call || !ts.isCallExpression(call) || call.expression !== reads[0])
		return "uses fork in one call alone";
	let plain = false;
	try {
		plain = lstatSync(join(dir, helper)).isFile();
	} catch {}
	if (dirname(helper) !== dirname(starter) || !helper.endsWith(".mjs") || !plain)
		return "forks names a helper beside it, a plain .mjs file";
	const joinBinding = namedImport(file, "node:path", "join").local;
	const joinSymbol = joinBinding && checker.getSymbolAtLocation(joinBinding);
	const [named, args, options, ...more] = call.arguments;
	const namedOk =
		joinSymbol !== undefined &&
		named !== undefined &&
		ts.isCallExpression(named) &&
		ts.isIdentifier(named.expression) &&
		checker.getSymbolAtLocation(named.expression) === joinSymbol &&
		named.arguments.length === 2 &&
		isDirname(named.arguments[0]) &&
		isLiteral(named.arguments[1], basename(helper));
	if (!namedOk) return `names the helper as join(import.meta.dirname, "${basename(helper)}")`;
	const isProcess = (name: ts.Identifier) => isGlobal(checker, name, file);
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
export function importsLookupAlone(path: string, reaches: readonly string[]): boolean {
	const { file } = bound(path);
	const imports = file.statements.filter(ts.isImportDeclaration);
	const exportsFrom = file.statements.some((st) => ts.isExportDeclaration(st));
	return (
		imports.length === 1 &&
		!exportsFrom &&
		!loadsAtRunTime(file) &&
		namedImport(file, "node:dns/promises", "lookup").alone &&
		reaches.every((reach) => reach === helperReach)
	);
}
