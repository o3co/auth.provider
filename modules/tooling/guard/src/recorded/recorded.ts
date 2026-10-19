import { join, resolve, sep } from "node:path";
import ts from "typescript";
import { importsOf, packageOf } from "../source.ts";
import { budgetsAsTest, type Scope } from "../units.ts";

const options: ts.CompilerOptions = {
	target: ts.ScriptTarget.ES2022,
	module: ts.ModuleKind.ESNext,
	moduleResolution: ts.ModuleResolutionKind.Bundler,
	allowImportingTsExtensions: true,
	noEmit: true,
	strict: true,
	skipLibCheck: true,
	types: [],
};

export interface Call {
	readonly file: string;
	readonly line: number;
	/** The call's receiver and method, as written. */
	readonly text: string;
}

/**
 * The calls in `files` that resolve, by type, to a method named `method` of an interface declared
 * in `dir`; `paths` maps the workspace's package names to their entries. A value of no known type
 * resolves to nothing and is not counted.
 */
function callsTo(
	files: readonly string[],
	paths: Readonly<Record<string, readonly string[]>>,
	dir: string,
	method: string,
): Call[] {
	const mapped = Object.fromEntries(Object.entries(paths).map(([name, to]) => [name, [...to]]));
	const program = ts.createProgram(files, { ...options, paths: mapped });
	const checker = program.getTypeChecker();
	const inside = (node: ts.Node) =>
		resolve(node.getSourceFile().fileName).startsWith(resolve(dir) + sep);
	const calls: Call[] = [];
	for (const file of files) {
		const source = program.getSourceFile(file);
		if (!source) continue;
		const visit = (node: ts.Node): void => {
			if (
				ts.isCallExpression(node) &&
				ts.isPropertyAccessExpression(node.expression) &&
				node.expression.name.text === method
			) {
				const declaration = checker.getResolvedSignature(node)?.getDeclaration();
				if (
					declaration !== undefined &&
					ts.isMethodSignature(declaration) &&
					ts.isInterfaceDeclaration(declaration.parent) &&
					inside(declaration)
				) {
					const { line } = source.getLineAndCharacterOfPosition(node.getStart());
					calls.push({ file, line: line + 1, text: node.expression.getText() });
				}
			}
			ts.forEachChild(node, visit);
		};
		visit(source);
	}
	return calls;
}

/** G30: outside the package `./audit-events` declare through, an event is recorded only through its declared wrapper. */
export function declaredRecordRules(s: Scope) {
	const rule = "G30 an audit event is recorded through declaredAudit";
	const declaring = new Set(
		s.packages.flatMap((p) => {
			const events = p.manifest.exports?.["./audit-events"];
			if (!events) return [];
			return importsOf(join(p.dir, events))
				.map((use) => packageOf(use.specifier)?.name ?? "")
				.filter((name) => s.byName.has(name));
		}),
	);
	const paths = Object.fromEntries(
		s.packages.flatMap((p) => {
			const entry = p.manifest.exports?.["."];
			return entry ? [[p.name, [join(p.dir, entry)]]] : [];
		}),
	);
	for (const name of declaring) {
		const owner = s.byName.get(name);
		if (!owner) continue;
		for (const p of s.packages) {
			if (p === owner || !(name in (p.manifest.dependencies ?? {}))) continue;
			const shipped = s
				.sources(p)
				.filter((file) => file.endsWith(".ts") && !budgetsAsTest(s, p, file))
				.map((file) => join(p.dir, file));
			for (const call of callsTo(shipped, paths, owner.dir, "record")) {
				const file = call.file.slice(p.dir.length + 1);
				s.report(rule, `${p.name}/${file}:${call.line}`, call.text);
			}
		}
	}
}
