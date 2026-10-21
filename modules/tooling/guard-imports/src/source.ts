import { readFileSync } from "node:fs";
import ts from "typescript";

export interface ImportUse {
	readonly specifier: string;
	readonly typeOnly: boolean;
}

/** A source file's syntax tree, read from disk. */
export function parse(path: string): ts.SourceFile {
	return ts.createSourceFile(path, readFileSync(path, "utf8"), ts.ScriptTarget.Latest, true);
}

function namedAreAllTypes(named: ts.NamedImportBindings | ts.NamedExportBindings | undefined) {
	return (
		named !== undefined &&
		(ts.isNamedImports(named) || ts.isNamedExports(named)) &&
		named.elements.length > 0 &&
		named.elements.every((element) => element.isTypeOnly)
	);
}

export function importsOf(path: string): ImportUse[] {
	const uses: ImportUse[] = [];
	const visit = (node: ts.Node): void => {
		if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
			const clause = node.importClause;
			const typeOnly =
				clause !== undefined &&
				(clause.isTypeOnly || (!clause.name && namedAreAllTypes(clause.namedBindings)));
			uses.push({ specifier: node.moduleSpecifier.text, typeOnly });
		} else if (
			ts.isExportDeclaration(node) &&
			node.moduleSpecifier &&
			ts.isStringLiteral(node.moduleSpecifier)
		) {
			const typeOnly = node.isTypeOnly || namedAreAllTypes(node.exportClause);
			uses.push({ specifier: node.moduleSpecifier.text, typeOnly });
		} else if (
			ts.isCallExpression(node) &&
			node.expression.kind === ts.SyntaxKind.ImportKeyword &&
			node.arguments[0] &&
			ts.isStringLiteral(node.arguments[0])
		) {
			uses.push({ specifier: node.arguments[0].text, typeOnly: false });
		}
		ts.forEachChild(node, visit);
	};
	visit(parse(path));
	return uses;
}

/** Local names a file brings in through its imports. */
export function importedNames(path: string): Set<string> {
	const names = new Set<string>();
	for (const statement of parse(path).statements) {
		if (!ts.isImportDeclaration(statement) || !statement.importClause) continue;
		const clause = statement.importClause;
		if (clause.name) names.add(clause.name.text);
		const named = clause.namedBindings;
		if (named && ts.isNamespaceImport(named)) names.add(named.name.text);
		if (named && ts.isNamedImports(named)) {
			for (const element of named.elements) names.add(element.name.text);
		}
	}
	return names;
}

/** The names a file takes from `from` as values, by their exported names; `*` for the whole module. */
export function valuesFrom(path: string, from: string): string[] {
	const names: string[] = [];
	for (const statement of parse(path).statements) {
		const clause = ts.isImportDeclaration(statement)
			? statement.importClause
			: ts.isExportDeclaration(statement)
				? statement
				: undefined;
		const specifier = (statement as ts.ImportDeclaration | ts.ExportDeclaration).moduleSpecifier;
		if (!clause || clause.isTypeOnly || !specifier || !ts.isStringLiteral(specifier)) continue;
		if (specifier.text !== from) continue;
		if (ts.isImportClause(clause) && clause.name) names.push("default");
		const bound = ts.isImportClause(clause) ? clause.namedBindings : clause.exportClause;
		if (!bound || ts.isNamespaceImport(bound) || ts.isNamespaceExport(bound)) names.push("*");
		else
			for (const element of bound.elements) {
				if (!element.isTypeOnly) names.push((element.propertyName ?? element.name).text);
			}
	}
	return names;
}

/** The names imported from `from` that a `keyof typeof` of the file keys by. */
export function keyedByImports(path: string, from: string): string[] {
	const file = parse(path);
	const bound = new Set(
		file.statements
			.filter(ts.isImportDeclaration)
			.filter((d) => ts.isStringLiteral(d.moduleSpecifier) && d.moduleSpecifier.text === from)
			.flatMap((d) => {
				const named = d.importClause?.namedBindings;
				return named && ts.isNamedImports(named) ? named.elements.map((e) => e.name.text) : [];
			}),
	);
	const keyed: string[] = [];
	const visit = (node: ts.Node): void => {
		if (
			ts.isTypeOperatorNode(node) &&
			node.operator === ts.SyntaxKind.KeyOfKeyword &&
			ts.isTypeQueryNode(node.type) &&
			ts.isIdentifier(node.type.exprName) &&
			bound.has(node.type.exprName.text)
		) {
			keyed.push(node.type.exprName.text);
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return keyed;
}

/** The package a specifier names, and the subpath within it; none for a relative or a Node one. */
export function packageOf(specifier: string): { name: string; subpath: string } | undefined {
	if (specifier.startsWith(".") || specifier.startsWith("node:")) return undefined;
	const parts = specifier.split("/");
	const size = specifier.startsWith("@") ? 2 : 1;
	return { name: parts.slice(0, size).join("/"), subpath: parts.slice(size).join("/") };
}
