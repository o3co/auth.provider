import { readFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { budgetsAsTest, type Scope } from "../scope.ts";
import type { Pkg } from "../workspace.ts";

const options: ts.CompilerOptions = {
	target: ts.ScriptTarget.ES2022,
	module: ts.ModuleKind.ESNext,
	moduleResolution: ts.ModuleResolutionKind.Bundler,
	allowImportingTsExtensions: true,
	noEmit: true,
	allowJs: true,
	strict: true,
	skipLibCheck: true,
	types: [],
};

/** Where shipped code writes an `internal` property: its file and line. */
interface Written {
	readonly pkg: Pkg;
	readonly file: string;
	readonly line: number;
}

/** Whether a type holds a type parameter anywhere: in a union or intersection, a template, a mapped string, or as one. */
const holdsTypeParameter = (type: ts.Type): boolean => {
	const deferred =
		ts.TypeFlags.TypeParameter |
		ts.TypeFlags.Index |
		ts.TypeFlags.IndexedAccess |
		ts.TypeFlags.Conditional |
		ts.TypeFlags.Substitution;
	if (type.flags & deferred) return true;
	if (type.isUnionOrIntersection()) return type.types.some(holdsTypeParameter);
	if (type.flags & ts.TypeFlags.TemplateLiteral)
		return (type as ts.TemplateLiteralType).types.some(holdsTypeParameter);
	if (type.flags & ts.TypeFlags.StringMapping)
		return holdsTypeParameter((type as ts.StringMappingType).type);
	return false;
};

/**
 * Whether a key may be the owned property's name: by name, or by a computed key whose type that name
 * fits (a union, a template, a mapped string or a string of no known value alike). A key whose type
 * holds a type parameter is read by what it may be bound to: its constraint, unknown for a bare one.
 */
const namesOwned = (checker: ts.TypeChecker, name: ts.PropertyName | undefined, owned: string) => {
	if (name === undefined) return false;
	if (!ts.isComputedPropertyName(name)) {
		return (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === owned;
	}
	return keyNames(checker, name.expression, owned);
};

/** Whether a key written as an expression (a computed key, an element access) may be the owned name. */
const keyNames = (checker: ts.TypeChecker, expression: ts.Expression, owned: string) => {
	const key = checker.getTypeAtLocation(expression);
	const literal = checker.getStringLiteralType(owned);
	if (holdsTypeParameter(key)) {
		const constraint = checker.getBaseConstraintOfType(key);
		return constraint === undefined || checker.isTypeAssignableTo(literal, constraint);
	}
	return checker.isTypeAssignableTo(literal, key);
};

/** The operators that write their left side. */
const assigns = new Set([
	ts.SyntaxKind.EqualsToken,
	ts.SyntaxKind.QuestionQuestionEqualsToken,
	ts.SyntaxKind.BarBarEqualsToken,
	ts.SyntaxKind.AmpersandAmpersandEqualsToken,
]);

/** The type of the value a property is written with: its initializer, its shorthand name, or its getter's return. */
const writtenType = (checker: ts.TypeChecker, property: ts.ObjectLiteralElementLike) => {
	if (ts.isPropertyAssignment(property)) return checker.getTypeAtLocation(property.initializer);
	if (ts.isShorthandPropertyAssignment(property)) return checker.getTypeAtLocation(property.name);
	if (ts.isGetAccessorDeclaration(property)) {
		const signature = checker.getSignatureFromDeclaration(property);
		return signature && checker.getReturnTypeOfSignature(signature);
	}
	return undefined;
};

/** What an owner holds to declaration: its package, and the type its contract exports with the property. */
interface Owned {
	readonly owner: Pkg;
	readonly type: string;
	readonly property: string;
}

/**
 * Each object literal property of the owned property's name, in the shipped code of `packages`,
 * whose value is of the type the owner's type gives that property (`undefined` aside); a value of no
 * known type (`any`) or of none (`never`) is not counted.
 */
function writtenIn(
	s: Scope,
	{ owner, type, property: owned }: Owned,
	packages: readonly Pkg[],
): Written[] | string {
	const paths = Object.fromEntries(
		s.packages.flatMap((p) => {
			const entry = p.manifest.exports?.["."];
			return entry ? [[p.name, [join(p.dir, entry)]]] : [];
		}),
	);
	const entry = owner.manifest.exports?.["."];
	if (entry === undefined) return "exports no contract";
	const files = packages.flatMap((p) =>
		s
			.sources(p)
			.filter(
				(file) => (file.endsWith(".ts") || file.endsWith(".mjs")) && !budgetsAsTest(s, p, file),
			)
			.map((file) => ({ p, path: join(p.dir, file), file })),
	);
	const ownerEntry = join(owner.dir, entry);
	const program = ts.createProgram([ownerEntry, ...files.map((f) => f.path)], {
		...options,
		paths,
	});
	const checker = program.getTypeChecker();
	// The owner's type as its contract exports it, wherever it is declared.
	const contract = program.getSourceFile(ownerEntry);
	const module = contract && checker.getSymbolAtLocation(contract);
	const exported = module && checker.getExportsOfModule(module).find((e) => e.name === type);
	const declared =
		exported && exported.flags & ts.SymbolFlags.Alias
			? checker.getAliasedSymbol(exported)
			: exported;
	const property = declared && checker.getDeclaredTypeOfSymbol(declared).getProperty(owned);
	if (property === undefined) return `exports no ${type} with ${owned}`;
	const wanted = checker.getNonNullableType(checker.getTypeOfSymbol(property));
	const written: Written[] = [];
	for (const { p, path, file } of files) {
		const source = program.getSourceFile(path);
		if (!source) continue;
		/** Records a write at `at` where its value, `undefined` aside, is of the property's type. */
		const count = (at: ts.Node, value: ts.Type | undefined) => {
			if (value === undefined) return;
			const type = checker.getNonNullableType(value);
			if (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Never | ts.TypeFlags.Unknown)) return;
			// A type parameter is read by what it may be bound to: the helper writes it, whoever calls.
			const generic = holdsTypeParameter(type);
			const constraint = generic ? checker.getBaseConstraintOfType(type) : undefined;
			const bindable =
				generic && (constraint === undefined || checker.isTypeAssignableTo(wanted, constraint));
			if (!bindable && !checker.isTypeAssignableTo(type, wanted)) return;
			const { line } = source.getLineAndCharacterOfPosition(at.getStart());
			written.push({ pkg: p, file, line: line + 1 });
		};
		const visit = (node: ts.Node): void => {
			if (ts.isObjectLiteralExpression(node)) {
				for (const element of node.properties) {
					if (namesOwned(checker, element.name, owned))
						count(element, writtenType(checker, element));
				}
			} else if (ts.isBinaryExpression(node) && assigns.has(node.operatorToken.kind)) {
				// An assignment to the property, by name or by an element access.
				const target = node.left;
				const named =
					(ts.isPropertyAccessExpression(target) && target.name.text === owned) ||
					(ts.isElementAccessExpression(target) &&
						keyNames(checker, target.argumentExpression, owned));
				if (named) count(node, checker.getTypeAtLocation(node.right));
			} else if (ts.isPropertyDeclaration(node) && node.initializer !== undefined) {
				// A class field initialised under the property's name.
				if (namesOwned(checker, node.name, owned))
					count(node, checker.getTypeAtLocation(node.initializer));
			} else if (ts.isParameterPropertyDeclaration(node, node.parent)) {
				// A constructor's parameter property, written by whoever constructs it.
				if (namesOwned(checker, node.name as ts.PropertyName, owned))
					count(node, checker.getTypeAtLocation(node));
			}
			ts.forEachChild(node, visit);
		};
		visit(source);
	}
	return [...written, ...templatedIn(s, owned, packages)];
}

/** A file that becomes a source once filled: a `.ts` or `.mjs` name under a suffix of its own. */
const isTemplate = (file: string) => /\.(?:ts|mjs)\.[^./]+$/.test(file);

/**
 * Each object literal property of the owned property's name in the templates of `packages`, by name
 * alone: a template's imports are filled in when it is written out, so its values have no type to
 * read. A computed key counts unless it is a literal of another name.
 */
function templatedIn(s: Scope, owned: string, packages: readonly Pkg[]): Written[] {
	const written: Written[] = [];
	for (const p of packages) {
		for (const file of p.files.filter((f) => isTemplate(f) && !budgetsAsTest(s, p, f))) {
			const source = ts.createSourceFile(
				file,
				readFileSync(join(p.dir, file), "utf8"),
				ts.ScriptTarget.ES2022,
				false,
				ts.ScriptKind.TS,
			);
			const named = (name: ts.PropertyName) => {
				if (!ts.isComputedPropertyName(name)) {
					return (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === owned;
				}
				const key = name.expression;
				return !(ts.isStringLiteralLike(key) || ts.isNumericLiteral(key)) || key.text === owned;
			};
			const visit = (node: ts.Node): void => {
				if (ts.isObjectLiteralExpression(node)) {
					for (const element of node.properties) {
						if (element.name === undefined || !named(element.name)) continue;
						const { line } = source.getLineAndCharacterOfPosition(element.getStart(source));
						written.push({ pkg: p, file, line: line + 1 });
					}
				}
				ts.forEachChild(node, visit);
			};
			visit(source);
		}
	}
	return written;
}

/** An owner's statement of what it holds to declaration, `{ type, property }`, or none where it is not one. */
const ownedOf = (value: unknown): { type: string; property: string } | undefined => {
	if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
	const { type, property } = value as Record<string, unknown>;
	return typeof type === "string" && typeof property === "string" && type !== "" && property !== ""
		? { type, property }
		: undefined;
};

/**
 * G32: shipped code writes the property an owner holds to declaration (the narrower's `internal`,
 * which reaches private addresses) only in the packages that declare it, `narrower` in their manifest
 * stating the property and their card stating that; each declaring package writes one. The owner
 * states the type and the property in its own `narrower`.
 */
export function internalByRules(s: Scope) {
	const rule = "G32 an owned property is written only by the packages declaring it";
	const owners: Owned[] = [];
	const declaring: Pkg[] = [];
	for (const p of s.packages) {
		const value = p.manifest.narrower;
		if (value === undefined) continue;
		// An object is an owner's statement; anything else, a writer's declaration.
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			declaring.push(p);
			continue;
		}
		const owned = ownedOf(value);
		if (owned === undefined) {
			s.report(rule, p.name, "narrower names no type and property it holds to declaration");
		} else {
			owners.push({ owner: p, ...owned });
		}
	}
	// The workspace's rules say how many owners there must be: none stating it leaves writes unheld.
	const required = s.budget.declaredProperties ?? 0;
	if (owners.length < required) {
		s.report(
			rule,
			"workspace",
			`${required} package(s) must state what they hold to declaration, ${owners.length} do`,
		);
	}
	const [owned, ...others] = owners;
	if (owned === undefined) {
		for (const p of declaring) {
			s.report(rule, p.name, `narrower: ${String(p.manifest.narrower)}, but no package owns it`);
		}
		return;
	}
	for (const other of others) {
		s.report(rule, owned.owner.name, `narrower: ${other.owner.name} states it owns it too`);
	}
	if (others.length > 0) return;
	const { property } = owned;
	const declared = new Set<string>();
	for (const p of declaring) {
		const value = p.manifest.narrower;
		if (value !== property) {
			s.report(
				rule,
				p.name,
				`narrower is ${JSON.stringify(value)}, not exactly ${JSON.stringify(property)}`,
			);
			continue;
		}
		declared.add(p.name);
		if (!(p.card ?? "").includes(`\`narrower\`: \`${property}\``)) {
			s.report(rule, p.name, `card states \`narrower\`: \`${property}\``);
		}
	}
	// The owner too: it states the property, and writes none.
	const written = writtenIn(s, owned, s.packages);
	if (typeof written === "string") {
		s.report(rule, owned.owner.name, `narrower, but it ${written}`);
		return;
	}
	for (const name of declared) {
		if (!written.some((w) => w.pkg.name === name)) {
			s.report(rule, name, `narrower: ${property}, but it writes none`);
		}
	}
	for (const w of written.filter((w) => !declared.has(w.pkg.name))) {
		s.report(rule, `${w.pkg.name}/${w.file}:${w.line}`, property);
	}
}
