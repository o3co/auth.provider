import { relative, resolve, sep } from "node:path";
import ts from "typescript";
import { host, options } from "./host.ts";

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
	/**
	 * Each export's carried types: the types the entry exports that its signature names by symbol,
	 * as written or, for a value, as inferred; the rest of its named references are `hidden`.
	 */
	readonly carries: ReadonlyMap<string, ReadonlySet<string>>;
}

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
	const program = ts.createProgram([entry], options, host);
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
	const carries = new Map<string, ReadonlySet<string>>();
	if (!moduleSymbol) {
		return { values, types, hidden: [], members: 0, tokens, points, docs, signatures, carries };
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
	/** The exported declarations, a type's by the name the entry exports it as. */
	const exportedDeclarations = new Set<ts.Node>();
	const exportedTypes = new Map<ts.Node, string>();
	/** The package's named types a symbol names: each exported one by its exported name, each other as `hidden`. */
	const sort = (referenced: ts.Symbol | undefined, symbol: ts.Symbol, carried: Set<string>) => {
		for (const d of referenced ? (resolveAlias(referenced).declarations ?? []) : []) {
			const name = exportedTypes.get(d);
			if (name !== undefined) carried.add(name);
			else if (named(d) && inside(d) && !exportedDeclarations.has(d)) {
				hidden.add(`${(d as ts.NamedDeclaration).name?.getText() ?? "?"} (${symbol.name})`);
			}
		}
	};
	/** A declaration's signature as written: each named type it refers to, sorted. */
	const referencesIn = (declaration: ts.Declaration, symbol: ts.Symbol, carried: Set<string>) => {
		const visit = (node: ts.Node): void => {
			if (ts.isTypeReferenceNode(node))
				sort(checker.getSymbolAtLocation(node.typeName), symbol, carried);
			if (ts.isExpressionWithTypeArguments(node)) {
				sort(checker.getSymbolAtLocation(node.expression), symbol, carried);
			}
			ts.forEachChild(node, visit);
		};
		for (const part of signatureParts(declaration)) visit(part);
	};
	const nameable =
		ts.SymbolFlags.Interface |
		ts.SymbolFlags.TypeAlias |
		ts.SymbolFlags.Class |
		ts.SymbolFlags.Enum;
	/** A value's type as inferred: the exported types it names, stopping at a named type (one outside the package at its arguments). */
	const inferredIn = (type: ts.Type, carried: Set<string>, seen = new Set<ts.Type>()): void => {
		if (seen.has(type)) return;
		seen.add(type);
		const next = (t: ts.Type) => inferredIn(t, carried, seen);
		const name = (s: ts.Symbol) =>
			(s.declarations ?? []).map((d) => exportedTypes.get(d)).find(Boolean);
		if (type.aliasSymbol) {
			const own = name(resolveAlias(type.aliasSymbol));
			if (own) carried.add(own);
			else (type.aliasTypeArguments ?? []).forEach(next);
			return;
		}
		if (type.isUnionOrIntersection()) {
			type.types.forEach(next);
			return;
		}
		if (!(type.flags & ts.TypeFlags.Object)) return;
		const symbol = type.getSymbol();
		if (symbol && symbol.flags & nameable) {
			const own = name(symbol);
			if (own) carried.add(own);
			else checker.getTypeArguments(type as ts.TypeReference).forEach(next);
			return;
		}
		for (const s of [...type.getCallSignatures(), ...type.getConstructSignatures()]) {
			for (const p of s.getParameters()) next(checker.getTypeOfSymbol(p));
			next(s.getReturnType());
		}
		for (const member of type.getProperties()) next(checker.getTypeOfSymbol(member));
	};
	for (const symbol of exported) {
		const target = resolveAlias(symbol);
		for (const declaration of target.declarations ?? []) exportedDeclarations.add(declaration);
		documented(target);
		(target.flags & ts.SymbolFlags.Value ? values : types).add(symbol.name);
		if (!(target.flags & ts.SymbolFlags.Value)) {
			for (const declaration of target.declarations ?? [])
				exportedTypes.set(declaration, symbol.name);
		}
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
		const target = resolveAlias(symbol);
		const carried = new Set<string>();
		for (const declaration of (target.declarations ?? []).filter(inside)) {
			referencesIn(declaration, symbol, carried);
		}
		if (target.flags & ts.SymbolFlags.Value) inferredIn(checker.getTypeOfSymbol(target), carried);
		carried.delete(symbol.name);
		carries.set(symbol.name, carried);
	}
	return {
		values,
		types,
		hidden: [...hidden].sort(),
		members,
		tokens,
		points,
		docs,
		signatures,
		carries,
	};
}
