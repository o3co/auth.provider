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

export { packageOf } from "./facts/facts.ts";
