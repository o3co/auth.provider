import { relative, resolve, sep } from "node:path";
import ts from "typescript";

export interface Surface {
	readonly values: ReadonlySet<string>;
	readonly types: ReadonlySet<string>;
	/** Types declared in the package that a public signature uses but the entry does not export. */
	readonly hidden: readonly string[];
	/** The members of the exported interfaces and type aliases, together. */
	readonly members: number;
	/** The exported values made by the kernel's `contract` or `extensionPoint`. */
	readonly tokens: ReadonlySet<string>;
	/** Those made by `extensionPoint`: the points other modules contribute to. */
	readonly points: ReadonlySet<string>;
	/** The doc comments on the exported declarations and their members, by file of the package: where each starts. */
	readonly docs: ReadonlyMap<string, ReadonlySet<number>>;
}

const options: ts.CompilerOptions = {
	target: ts.ScriptTarget.ES2022,
	module: ts.ModuleKind.NodeNext,
	moduleResolution: ts.ModuleResolutionKind.NodeNext,
	allowImportingTsExtensions: true,
	noEmit: true,
	strict: true,
	skipLibCheck: true,
	types: [],
};

const named = (node: ts.Node) =>
	ts.isInterfaceDeclaration(node) ||
	ts.isTypeAliasDeclaration(node) ||
	ts.isClassDeclaration(node) ||
	ts.isEnumDeclaration(node);

const madeBy = (makers: readonly string[]) => (node: ts.Node) =>
	ts.isVariableDeclaration(node) &&
	node.initializer !== undefined &&
	ts.isCallExpression(node.initializer) &&
	ts.isIdentifier(node.initializer.expression) &&
	makers.includes(node.initializer.expression.text);
const madeAsToken = madeBy(["contract", "extensionPoint"]);
const madeAsPoint = madeBy(["extensionPoint"]);

/** The parts of a declaration that make up its signature, without function bodies. */
function signatureParts(node: ts.Node): ts.Node[] {
	if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isArrowFunction(node)) {
		return [...(node.typeParameters ?? []), ...node.parameters, ...(node.type ? [node.type] : [])];
	}
	if (ts.isVariableDeclaration(node)) return node.type ? [node.type] : [];
	if (ts.isClassDeclaration(node)) {
		return node.members.flatMap((member) =>
			ts.isMethodDeclaration(member)
				? signatureParts(member)
				: ts.isPropertyDeclaration(member) && member.type
					? [member.type]
					: [],
		);
	}
	return [node];
}

export function surfaceOf(entry: string, packageDir: string): Surface {
	const program = ts.createProgram([entry], options);
	const checker = program.getTypeChecker();
	const source = program.getSourceFile(entry);
	const moduleSymbol = source && checker.getSymbolAtLocation(source);
	const values = new Set<string>();
	const types = new Set<string>();
	const tokens = new Set<string>();
	const points = new Set<string>();
	const hidden = new Set<string>();
	const docs = new Map<string, Set<number>>();
	if (!moduleSymbol) return { values, types, hidden: [], members: 0, tokens, points, docs };
	let members = 0;
	// A primitive, or a union of them, has no members of its own: the platform's own are not the contract's.
	const primitives =
		ts.TypeFlags.StringLike |
		ts.TypeFlags.NumberLike |
		ts.TypeFlags.BigIntLike |
		ts.TypeFlags.BooleanLike |
		ts.TypeFlags.ESSymbolLike |
		ts.TypeFlags.Null |
		ts.TypeFlags.Undefined |
		ts.TypeFlags.Void;
	const primitive = (type: ts.Type): boolean =>
		type.isUnion() ? type.types.every(primitive) : (type.flags & primitives) !== 0;
	const resolveAlias = (symbol: ts.Symbol) =>
		symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
	const inside = (node: ts.Node) => {
		const file = resolve(node.getSourceFile().fileName);
		return file.startsWith(resolve(packageDir) + sep) && !file.includes(`${sep}node_modules${sep}`);
	};
	const documented = (symbol: ts.Symbol) => {
		for (const declaration of (symbol.declarations ?? []).filter(inside)) {
			const file = relative(resolve(packageDir), resolve(declaration.getSourceFile().fileName));
			const starts = docs.get(file) ?? new Set<number>();
			for (const doc of ts.getJSDocCommentsAndTags(declaration).filter(ts.isJSDoc)) {
				starts.add(doc.pos);
			}
			docs.set(file, starts);
		}
	};
	const exported = checker.getExportsOfModule(moduleSymbol);
	const exportedDeclarations = new Set<ts.Node>();
	for (const symbol of exported) {
		const target = resolveAlias(symbol);
		for (const declaration of target.declarations ?? []) exportedDeclarations.add(declaration);
		documented(target);
		(target.flags & ts.SymbolFlags.Value ? values : types).add(symbol.name);
		if ((target.declarations ?? []).some(madeAsToken)) tokens.add(symbol.name);
		if ((target.declarations ?? []).some(madeAsPoint)) points.add(symbol.name);
		if (target.flags & (ts.SymbolFlags.Interface | ts.SymbolFlags.TypeAlias)) {
			const type = checker.getDeclaredTypeOfSymbol(target);
			if (primitive(type)) continue;
			members += type.getProperties().length;
			for (const member of type.getProperties()) documented(member);
		}
	}
	for (const symbol of exported) {
		for (const declaration of resolveAlias(symbol).declarations ?? []) {
			if (!inside(declaration)) continue;
			const visit = (node: ts.Node): void => {
				if (ts.isTypeReferenceNode(node) || ts.isExpressionWithTypeArguments(node)) {
					const name = ts.isTypeReferenceNode(node) ? node.typeName : node.expression;
					const referenced = checker.getSymbolAtLocation(name);
					for (const d of referenced ? (resolveAlias(referenced).declarations ?? []) : []) {
						if (named(d) && inside(d) && !exportedDeclarations.has(d)) {
							hidden.add(`${(d as ts.NamedDeclaration).name?.getText() ?? "?"} (${symbol.name})`);
						}
					}
				}
				ts.forEachChild(node, visit);
			};
			for (const part of signatureParts(declaration)) visit(part);
		}
	}
	return { values, types, hidden: [...hidden].sort(), members, tokens, points, docs };
}
