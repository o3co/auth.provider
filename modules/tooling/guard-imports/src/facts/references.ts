import ts from "typescript";
import { ambient } from "./context.ts";
import type { Edge } from "./edges.ts";

/** What an identifier stands for where it is written (the card says each). */
export type Role =
	| "value"
	| "type"
	| "type-query"
	| "declared"
	| "property"
	| "attribute-key"
	| "label";

/** What a name is bound to: a declaration of the file, a name an edge binds, or none in its lexical scope. */
export type Binding =
	| { readonly kind: "local"; readonly declaration: ts.Node }
	| { readonly kind: "imported"; readonly edge: Edge; readonly name: string }
	| { readonly kind: "unbound"; readonly name: string };

export interface Reference {
	readonly node: ts.Identifier;
	readonly role: Role;
	/** For a value, a type, a type query or a declared name; none for a property, a key or a label. */
	readonly binding?: Binding;
}

/** A property read of a name, by a dot or a literal key: `globalThis.fetch`, `ns["x"]`. */
export interface MemberRead {
	readonly node: ts.PropertyAccessExpression | ts.ElementAccessExpression;
	readonly object: Reference;
	/** The property's name; none where it is computed. */
	readonly name?: string;
}

/** An expression with type arguments whose expression is run: a class's extends, an instantiation (`f<T>`). */
export const valueWithTypeArguments = (node: ts.Node): node is ts.ExpressionWithTypeArguments =>
	ts.isExpressionWithTypeArguments(node) &&
	!(
		ts.isHeritageClause(node.parent) &&
		!(node.parent.token === ts.SyntaxKind.ExtendsKeyword && ts.isClassLike(node.parent.parent))
	);

const within = (node: ts.Node, outer: ts.Node) => node.pos >= outer.pos && node.end <= outer.end;

/** Whether a name stands in a type's place: a type query, or any other type, never the value of an expression with type arguments. */
function typePlace(node: ts.Node): "type" | "type-query" | undefined {
	for (let at = node.parent; at !== undefined && !ts.isSourceFile(at); at = at.parent) {
		if (valueWithTypeArguments(at)) return within(node, at.expression) ? undefined : "type";
		if (ts.isTypeQueryNode(at)) return within(node, at.exprName) ? "type-query" : "type";
		if (ts.isTypeNode(at)) return "type";
	}
	return undefined;
}

/** Declarations whose `name` introduces a binding. */
const declares = (p: ts.Node) =>
	ts.isVariableDeclaration(p) ||
	ts.isParameter(p) ||
	ts.isFunctionDeclaration(p) ||
	ts.isFunctionExpression(p) ||
	ts.isClassDeclaration(p) ||
	ts.isClassExpression(p) ||
	ts.isInterfaceDeclaration(p) ||
	ts.isTypeAliasDeclaration(p) ||
	ts.isEnumDeclaration(p) ||
	ts.isTypeParameterDeclaration(p) ||
	ts.isModuleDeclaration(p) ||
	ts.isImportClause(p) ||
	ts.isNamespaceImport(p) ||
	ts.isImportEqualsDeclaration(p) ||
	ts.isNamespaceExport(p);
/** Members whose `name` is a property's name. */
const names = (p: ts.Node) =>
	ts.isPropertyAssignment(p) ||
	ts.isPropertyDeclaration(p) ||
	ts.isPropertySignature(p) ||
	ts.isMethodDeclaration(p) ||
	ts.isMethodSignature(p) ||
	ts.isGetAccessorDeclaration(p) ||
	ts.isSetAccessorDeclaration(p) ||
	ts.isEnumMember(p);

/** The role of an identifier by its place alone. */
function placeOf(id: ts.Identifier): Role {
	const p = id.parent;
	if (ts.isPropertyAccessExpression(p) && p.name === id) return "property";
	if (ts.isQualifiedName(p) && p.right === id) return "property";
	if (ts.isImportAttribute(p)) return "attribute-key";
	if (ts.isLabeledStatement(p) || ts.isBreakOrContinueStatement(p)) return "label";
	if (ts.isMetaProperty(p)) return "property";
	if (names(p) && (p as { name?: ts.Node }).name === id) return "property";
	if (ts.isBindingElement(p))
		return p.propertyName === id ? "property" : p.name === id ? "declared" : "value";
	if (ts.isImportSpecifier(p)) return p.propertyName === id ? "property" : "declared";
	if (ts.isExportSpecifier(p)) {
		// A re-export's names are the module's; a local export reads its first name and gives the second.
		if (p.parent.parent.moduleSpecifier) return "property";
		if (p.propertyName !== undefined && p.name === id) return "declared";
		// A name exported as a type alone is read as a type.
		return p.isTypeOnly || p.parent.parent.isTypeOnly ? "type" : "value";
	}
	if (declares(p) && (p as { name?: ts.Node }).name === id) return "declared";
	return typePlace(id) ?? "value";
}

/** The role of an identifier where it stands; a value's place in an ambient context is a type's, erased. */
export function roleOf(id: ts.Identifier): Role {
	const role = placeOf(id);
	return role === "value" && ambient(id) ? "type" : role;
}

/** The symbol a name reads: a shorthand property and a local export read the value they name. */
function symbolRead(checker: ts.TypeChecker, id: ts.Identifier): ts.Symbol | undefined {
	const p = id.parent;
	if (ts.isShorthandPropertyAssignment(p) && p.name === id) {
		return checker.getShorthandAssignmentValueSymbol(p);
	}
	if (ts.isExportSpecifier(p) && !p.parent.parent.moduleSpecifier) {
		return checker.getExportSpecifierLocalTargetSymbol(p);
	}
	return checker.getSymbolAtLocation(id);
}

/** What an identifier is bound to, by the declarations of its symbol in this file. */
function bindingOf(
	checker: ts.TypeChecker,
	file: ts.SourceFile,
	id: ts.Identifier,
	importedBy: ReadonlyMap<ts.Node, { edge: Edge; name: string }>,
): Binding {
	const here = (symbolRead(checker, id)?.declarations ?? []).filter(
		(d) => d.getSourceFile() === file,
	);
	const first = here[0];
	if (first === undefined) return { kind: "unbound", name: id.text };
	// An import names its binding by the declaration's name; a loader's result by the name it is bound to.
	const named = (first as { name?: ts.Node }).name;
	const imported = named === undefined ? undefined : importedBy.get(named);
	return imported ? { kind: "imported", ...imported } : { kind: "local", declaration: first };
}

/** Each identifier of a file with its role and binding, and each property read of a name. */
export function referencesOf(
	file: ts.SourceFile,
	checker: ts.TypeChecker,
	edges: readonly Edge[],
): { references: Reference[]; members: MemberRead[] } {
	// Each binding an edge makes, by the declaration that names it.
	const importedBy = new Map<ts.Node, { edge: Edge; name: string }>();
	for (const edge of edges) {
		for (const b of edge.bindings) {
			if (b.local) importedBy.set(b.local, { edge, name: b.imported });
		}
	}
	const references: Reference[] = [];
	const members: MemberRead[] = [];
	const visit = (node: ts.Node): void => {
		if (ts.isIdentifier(node)) {
			const role = roleOf(node);
			const bound = role === "property" || role === "attribute-key" || role === "label";
			const reference: Reference = bound
				? { node, role }
				: { node, role, binding: bindingOf(checker, file, node, importedBy) };
			references.push(reference);
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	for (const reference of references) {
		const p = reference.node.parent;
		const read =
			(ts.isPropertyAccessExpression(p) || ts.isElementAccessExpression(p)) &&
			p.expression === reference.node;
		if (!read) continue;
		const name = ts.isPropertyAccessExpression(p)
			? p.name.text
			: ts.isStringLiteralLike(p.argumentExpression)
				? p.argumentExpression.text
				: undefined;
		members.push({ node: p, object: reference, ...(name === undefined ? {} : { name }) });
	}
	return { references, members };
}
