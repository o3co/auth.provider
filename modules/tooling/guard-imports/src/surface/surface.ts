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
	/**
	 * Each export's structure, as text, by its name: a type's members (name, `readonly`, optional,
	 * type) sorted by name, with its calls, constructions and index signatures; a value's type; an
	 * enum's members and their values. Two surfaces' signatures differ wherever their contract does,
	 * whatever file a declaration lies in; a type a signature names by name has its own signature.
	 */
	readonly signatures: ReadonlyMap<string, string>;
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

/** How a signature writes a type: whole, and a function as an arrow. */
const written = ts.TypeFormatFlags.NoTruncation | ts.TypeFormatFlags.WriteArrowStyleSignature;

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
	const signatures = new Map<string, string>();
	if (!moduleSymbol) {
		return { values, types, hidden: [], members: 0, tokens, points, docs, signatures };
	}
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
	const text = (type: ts.Type, flags = ts.TypeFormatFlags.None) =>
		checker.typeToString(type, undefined, flags | written);
	/** A type's members, calls, constructions and index signatures, one line each, sorted. */
	const structure = (type: ts.Type): string[] => {
		const members = type.getProperties().map((member) => {
			const readonly =
				ts.getCombinedModifierFlags(
					member.valueDeclaration ?? member.declarations?.[0] ?? source!,
				) & ts.ModifierFlags.Readonly;
			const optional = member.flags & ts.SymbolFlags.Optional ? "?" : "";
			// A member keyed by a symbol is named as written (`[mark]`), never by the id one program gives it.
			const name = member.name.startsWith("__@") ? checker.symbolToString(member) : member.name;
			return `  ${readonly ? "readonly " : ""}${name}${optional}: ${text(checker.getTypeOfSymbol(member))}`;
		});
		const calls = type
			.getCallSignatures()
			.map((c) => `  call ${checker.signatureToString(c, undefined, written)}`);
		const builds = type
			.getConstructSignatures()
			.map((c) => `  new ${checker.signatureToString(c, undefined, written)}`);
		const indexes = checker
			.getIndexInfosOfType(type)
			.map((i) => `  [${text(i.keyType)}]: ${text(i.type)}`);
		return [...members, ...calls, ...builds, ...indexes].sort();
	};
	const parametersOf = (declaration: ts.Declaration | undefined) => {
		const listed =
			declaration &&
			(ts.isInterfaceDeclaration(declaration) ||
				ts.isTypeAliasDeclaration(declaration) ||
				ts.isClassDeclaration(declaration))
				? declaration.typeParameters
				: undefined;
		return listed ? `<${listed.map((p) => p.getText()).join(", ")}>` : "";
	};
	const signatureOf = (name: string, target: ts.Symbol): string => {
		const lines: string[] = [];
		const declaration = target.declarations?.[0];
		if (target.flags & ts.SymbolFlags.Enum) {
			const members = checker.getExportsOfModule(target).map((member) => {
				const value =
					member.valueDeclaration && ts.isEnumMember(member.valueDeclaration)
						? checker.getConstantValue(member.valueDeclaration)
						: undefined;
				return `  ${member.name} = ${JSON.stringify(value)}`;
			});
			return [`enum ${name}`, ...members.sort()].join("\n");
		}
		if (
			target.flags &
			(ts.SymbolFlags.Interface | ts.SymbolFlags.TypeAlias | ts.SymbolFlags.Class)
		) {
			const type = checker.getDeclaredTypeOfSymbol(target);
			const head = `${target.flags & ts.SymbolFlags.Class ? "class" : "type"} ${name}${parametersOf(declaration)}`;
			const object =
				(type.flags & ts.TypeFlags.Object) !== 0 &&
				!(
					target.flags & ts.SymbolFlags.TypeAlias &&
					type.getCallSignatures().length > 0 &&
					type.getProperties().length === 0
				);
			lines.push(
				object
					? [head, ...structure(type)].join("\n")
					: `${head} = ${text(type, ts.TypeFormatFlags.InTypeAlias)}`,
			);
		}
		if (target.flags & ts.SymbolFlags.Value && !(target.flags & ts.SymbolFlags.Enum)) {
			const type = checker.getTypeOfSymbol(target);
			lines.push(
				target.flags & ts.SymbolFlags.Class
					? `value ${name}\n${structure(type).join("\n")}`
					: `value ${name}: ${text(type)}`,
			);
		}
		return lines.join("\n");
	};
	const exported = checker.getExportsOfModule(moduleSymbol);
	const exportedDeclarations = new Set<ts.Node>();
	for (const symbol of exported) {
		const target = resolveAlias(symbol);
		for (const declaration of target.declarations ?? []) exportedDeclarations.add(declaration);
		documented(target);
		(target.flags & ts.SymbolFlags.Value ? values : types).add(symbol.name);
		signatures.set(symbol.name, signatureOf(symbol.name, target));
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
	return { values, types, hidden: [...hidden].sort(), members, tokens, points, docs, signatures };
}
