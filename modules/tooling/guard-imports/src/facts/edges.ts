import { dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { ambient } from "./context.ts";
import { esmTarget, realOf, requireTarget, type Target } from "./resolve.ts";

/** How a file reaches a module (the card says each). */
export type EdgeForm =
	| "import"
	| "export-from"
	| "dynamic-import"
	| "import-type"
	| "import-equals"
	| "require"
	| "resolve";

/** What a specifier says: its text, or the static part of one named at run time. */
export interface Specifier {
	readonly text?: string;
	readonly fragment?: string;
}

/** A name an edge binds or re-exports. */
export interface EdgeBinding {
	readonly form: "default" | "named" | "namespace" | "star" | "equals" | "whole" | "destructured";
	/** The name taken from the module: `default`, a name, or `*`. */
	readonly imported: string;
	/** The local name it is bound to, where one is. */
	readonly local?: ts.Identifier;
	/** The name a re-export gives it. */
	readonly exported?: string;
	readonly typeOnly: boolean;
}

export interface Edge {
	readonly form: EdgeForm;
	/** Where it is written, for a reader that reads more of it (a call's arguments). */
	readonly node: ts.Node;
	readonly specifier: Specifier;
	/** Whether the module is loaded at run time; a type, an ambient context or a resolve loads nothing. */
	readonly loads: boolean;
	readonly bindings: readonly EdgeBinding[];
	readonly target: Target;
	/** For a call of a loader: `require` unbound, or one `createRequire` made. */
	readonly loader?: "require" | "createRequire";
}

/** A specifier written as a literal, a template without a substitution, or neither. */
function specifierOf(node: ts.Node | undefined): Specifier {
	if (node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))) {
		return { text: node.text };
	}
	if (node && ts.isTemplateExpression(node)) return { fragment: node.head.text };
	return {};
}

/** How a specifier is resolved: as ESM from the file, or as `require` from a loader's base (none known). */
type Resolution = { readonly esm: string } | { readonly require: string | undefined };

/** A specifier's target, `computed` where it is named at run time. */
function targetOf(specifier: Specifier, by: Resolution): Target {
	if (specifier.text === undefined) {
		return {
			kind: "unresolved",
			reason: "computed",
			...(specifier.fragment === undefined ? {} : { fragment: specifier.fragment }),
		};
	}
	return "esm" in by
		? esmTarget(specifier.text, by.esm)
		: requireTarget(specifier.text, by.require);
}

/** An expression without the parentheses around it. */
export function skipParens(node: ts.Expression): ts.Expression {
	let at = node;
	while (ts.isParenthesizedExpression(at)) at = at.expression;
	return at;
}

/** The node an expression is part of, above the parentheses around it. */
function upParens(node: ts.Node): ts.Node {
	let at = node;
	while (ts.isParenthesizedExpression(at)) at = at.parent;
	return at;
}

const moduleNames = new Set(["node:module", "module"]);

/** A name's declarations in its own file: another file's declaration binds nothing here. */
const declaredHere = (checker: ts.TypeChecker, id: ts.Identifier) =>
	(checker.getSymbolAtLocation(id)?.declarations ?? []).filter(
		(d) => d.getSourceFile() === id.getSourceFile(),
	);

/** Whether a name is bound, in this file, to `createRequire` imported from node:module. */
function isCreateRequire(checker: ts.TypeChecker, callee: ts.Expression): boolean {
	const named = skipParens(callee);
	const declaration = (id: ts.Identifier) => declaredHere(checker, id)[0];
	const fromModule = (d: ts.Node | undefined) => {
		const statement = d && ts.findAncestor(d, ts.isImportDeclaration);
		return (
			statement !== undefined &&
			ts.isStringLiteral(statement.moduleSpecifier) &&
			moduleNames.has(statement.moduleSpecifier.text)
		);
	};
	if (ts.isIdentifier(named)) {
		const d = declaration(named);
		return (
			d !== undefined &&
			ts.isImportSpecifier(d) &&
			fromModule(d) &&
			(d.propertyName ?? d.name).text === "createRequire"
		);
	}
	if (ts.isPropertyAccessExpression(named) && named.name.text === "createRequire") {
		const owner = skipParens(named.expression);
		if (!ts.isIdentifier(owner)) return false;
		const d = declaration(owner);
		return d !== undefined && (ts.isNamespaceImport(d) || ts.isImportClause(d)) && fromModule(d);
	}
	return false;
}

/** The file a `createRequire` call resolves from: `import.meta.url`, an absolute path or a file URL; none known otherwise. */
/** The directory a module's own `require` resolves from: its real place's, as Node runs it. */
const ownDir = (file: string) => dirname(realOf(file));

/** The directory a loader `createRequire` made resolves from: the module's own for `import.meta.url`, else the one named as given (a directory where it ends in `/`, else a file's), unfollowed; none where unknown. */
function baseOf(call: ts.CallExpression): string | undefined {
	const named = givenOf(call);
	if (named === undefined || named === call.getSourceFile().fileName) {
		return named && ownDir(named);
	}
	return named.endsWith("/") ? named : dirname(named);
}

/** What `createRequire` was given, as a path: the module's file for `import.meta.url`, an absolute path or a file URL. */
function givenOf(call: ts.CallExpression): string | undefined {
	const given = call.arguments[0] && skipParens(call.arguments[0]);
	if (
		given &&
		ts.isPropertyAccessExpression(given) &&
		ts.isMetaProperty(given.expression) &&
		given.expression.keywordToken === ts.SyntaxKind.ImportKeyword &&
		given.name.text === "url"
	) {
		return call.getSourceFile().fileName;
	}
	if (!given || !(ts.isStringLiteral(given) || ts.isNoSubstitutionTemplateLiteral(given)))
		return undefined;
	if (given.text.startsWith("file:")) {
		try {
			return fileURLToPath(given.text);
		} catch {
			return undefined;
		}
	}
	return isAbsolute(given.text) ? given.text : undefined;
}

/** A loader a callee names, and the file it resolves from: `require` unbound in the file (from the file), or a name `createRequire` made (from its base, none where unknown). */
export function loaderOf(
	checker: ts.TypeChecker,
	callee: ts.Expression,
): { readonly loader: NonNullable<Edge["loader"]>; readonly base: string | undefined } | undefined {
	const named = skipParens(callee);
	if (!ts.isIdentifier(named)) return undefined;
	const declarations = declaredHere(checker, named);
	if (declarations.length === 0) {
		return named.text === "require"
			? { loader: "require", base: ownDir(named.getSourceFile().fileName) }
			: undefined;
	}
	const made = declarations.find(ts.isVariableDeclaration);
	const call = made?.initializer && skipParens(made.initializer);
	return call && ts.isCallExpression(call) && isCreateRequire(checker, call.expression)
		? { loader: "createRequire", base: baseOf(call) }
		: undefined;
}

/** What a loader's result is bound to: a name whole, or the properties taken from it. */
function requireBindings(call: ts.CallExpression): EdgeBinding[] {
	const parent = upParens(call.parent);
	if (!ts.isVariableDeclaration(parent) || parent.initializer === undefined) return [];
	const name = parent.name;
	if (ts.isIdentifier(name))
		return [{ form: "whole", imported: "*", local: name, typeOnly: false }];
	if (!ts.isObjectBindingPattern(name)) return [];
	return name.elements.flatMap((element): EdgeBinding[] => {
		// A rest takes what is left: the module whole, never a name of it.
		if (element.dotDotDotToken && ts.isIdentifier(element.name)) {
			return [{ form: "whole", imported: "*", local: element.name, typeOnly: false }];
		}
		const imported = element.propertyName ?? element.name;
		const named = ts.isIdentifier(imported) || ts.isStringLiteral(imported);
		if (!ts.isIdentifier(element.name) || !named) return [];
		return [
			{ form: "destructured", imported: imported.text, local: element.name, typeOnly: false },
		];
	});
}

/** The bindings of an import declaration, each with its own type-only. */
function importBindings(node: ts.ImportDeclaration): EdgeBinding[] {
	const clause = node.importClause;
	if (!clause) return [];
	const whole = clause.isTypeOnly;
	const named = clause.namedBindings;
	return [
		...(clause.name
			? [{ form: "default" as const, imported: "default", local: clause.name, typeOnly: whole }]
			: []),
		...(named && ts.isNamespaceImport(named)
			? [{ form: "namespace" as const, imported: "*", local: named.name, typeOnly: whole }]
			: []),
		...(named && ts.isNamedImports(named)
			? named.elements.map((e) => ({
					form: "named" as const,
					imported: (e.propertyName ?? e.name).text,
					local: e.name,
					typeOnly: whole || e.isTypeOnly,
				}))
			: []),
	];
}

/** The names a re-export takes and gives, each with its own type-only. */
function exportBindings(node: ts.ExportDeclaration): EdgeBinding[] {
	const whole = node.isTypeOnly;
	const clause = node.exportClause;
	if (!clause) return [{ form: "star", imported: "*", typeOnly: whole }];
	if (ts.isNamespaceExport(clause)) {
		return [{ form: "namespace", imported: "*", exported: clause.name.text, typeOnly: whole }];
	}
	return clause.elements.map((e) => ({
		form: "named",
		imported: (e.propertyName ?? e.name).text,
		exported: e.name.text,
		typeOnly: whole || e.isTypeOnly,
	}));
}

/** Each edge of a file, in the order written. */
export function edgesOf(file: ts.SourceFile, checker: ts.TypeChecker): Edge[] {
	const from = file.fileName;
	const edges: Edge[] = [];
	const add = (edge: Omit<Edge, "target">, by: Resolution = { esm: from }) =>
		edges.push({ ...edge, target: targetOf(edge.specifier, by) });
	const visit = (node: ts.Node): void => {
		if (ts.isImportDeclaration(node)) {
			add({
				form: "import",
				node,
				specifier: specifierOf(node.moduleSpecifier),
				loads: !node.importClause?.isTypeOnly && !ambient(node),
				bindings: importBindings(node),
			});
		} else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
			add({
				form: "export-from",
				node,
				specifier: specifierOf(node.moduleSpecifier),
				loads: !node.isTypeOnly && !ambient(node),
				bindings: exportBindings(node),
			});
		} else if (
			ts.isImportEqualsDeclaration(node) &&
			ts.isExternalModuleReference(node.moduleReference)
		) {
			const binding = { form: "equals" as const, imported: "*", local: node.name };
			add(
				{
					form: "import-equals",
					node,
					specifier: specifierOf(node.moduleReference.expression),
					loads: !node.isTypeOnly && !ambient(node),
					bindings: [{ ...binding, typeOnly: node.isTypeOnly }],
				},
				{ require: ownDir(from) },
			);
		} else if (ts.isImportTypeNode(node)) {
			const argument = ts.isLiteralTypeNode(node.argument) ? node.argument.literal : undefined;
			add({
				form: "import-type",
				node,
				specifier: specifierOf(argument),
				loads: false,
				bindings: [],
			});
		} else if (ts.isCallExpression(node)) {
			callEdge(node);
		}
		ts.forEachChild(node, visit);
	};
	/** A dynamic import, a loader's call, or a resolve. */
	const callEdge = (node: ts.CallExpression) => {
		const callee = skipParens(node.expression);
		const specifier = specifierOf(node.arguments[0]);
		if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
			add({ form: "dynamic-import", node, specifier, loads: !ambient(node), bindings: [] });
			return;
		}
		const made = loaderOf(checker, callee);
		if (made) {
			const { loader, base } = made;
			add(
				{
					form: "require",
					node,
					specifier,
					loads: !ambient(node),
					bindings: requireBindings(node),
					loader,
				},
				{ require: base },
			);
			return;
		}
		if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== "resolve") return;
		const owner = skipParens(callee.expression);
		if (ts.isMetaProperty(owner) && owner.keywordToken === ts.SyntaxKind.ImportKeyword) {
			add({ form: "resolve", node, specifier, loads: false, bindings: [] });
		} else {
			const made = loaderOf(checker, owner);
			if (made)
				add(
					{ form: "resolve", node, specifier, loads: false, bindings: [] },
					{ require: made.base },
				);
		}
	};
	visit(file);
	return edges;
}
