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

/**
 * Whether an object literal's property may be written under the name `internal`: by name, or by a
 * computed key whose type the string "internal" fits, a type parameter's by its constraint (a
 * union, a template, a mapped string or a string of no known value alike).
 */
const namesInternal = (checker: ts.TypeChecker, property: ts.ObjectLiteralElementLike) => {
	const name = property.name;
	if (name === undefined) return false;
	if (!ts.isComputedPropertyName(name)) {
		return (ts.isIdentifier(name) || ts.isStringLiteralLike(name)) && name.text === "internal";
	}
	const key = checker.getTypeAtLocation(name.expression);
	const bound = key.isTypeParameter() ? (checker.getBaseConstraintOfType(key) ?? key) : key;
	return checker.isTypeAssignableTo(checker.getStringLiteralType("internal"), bound);
};

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

/**
 * Each object literal property named `internal`, in the shipped code of `packages`, whose value is
 * of the type the owner's `Narrower.internal` takes (`undefined` aside); a value of no known type
 * (`any`) or of none (`never`) is not counted.
 */
function writtenIn(s: Scope, owner: Pkg, packages: readonly Pkg[]): Written[] | string {
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
			.filter((file) => file.endsWith(".ts") && !budgetsAsTest(s, p, file))
			.map((file) => ({ p, path: join(p.dir, file), file })),
	);
	const ownerEntry = join(owner.dir, entry);
	const program = ts.createProgram([ownerEntry, ...files.map((f) => f.path)], {
		...options,
		paths,
	});
	const checker = program.getTypeChecker();
	// `Narrower` as the contract exports it, wherever it is declared.
	const contract = program.getSourceFile(ownerEntry);
	const module = contract && checker.getSymbolAtLocation(contract);
	const exported = module && checker.getExportsOfModule(module).find((e) => e.name === "Narrower");
	const narrower =
		exported && exported.flags & ts.SymbolFlags.Alias
			? checker.getAliasedSymbol(exported)
			: exported;
	const property = narrower && checker.getDeclaredTypeOfSymbol(narrower).getProperty("internal");
	if (property === undefined) return "exports no Narrower with internal";
	const wanted = checker.getNonNullableType(checker.getTypeOfSymbol(property));
	const written: Written[] = [];
	for (const { p, path, file } of files) {
		const source = program.getSourceFile(path);
		if (!source) continue;
		const visit = (node: ts.Node): void => {
			if (ts.isObjectLiteralExpression(node)) {
				for (const element of node.properties) {
					if (!namesInternal(checker, element)) continue;
					const value = writtenType(checker, element);
					if (value === undefined) continue;
					const type = checker.getNonNullableType(value);
					if (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Never | ts.TypeFlags.Unknown)) continue;
					if (!checker.isTypeAssignableTo(type, wanted)) continue;
					const { line } = source.getLineAndCharacterOfPosition(element.getStart());
					written.push({ pkg: p, file, line: line + 1 });
				}
			}
			ts.forEachChild(node, visit);
		};
		visit(source);
	}
	return written;
}

/**
 * G32: shipped code writes the narrower's `internal`, which reaches private addresses, only in the
 * packages its owner's manifest lists in `internalBy`; each listed package writes one.
 */
export function internalByRules(s: Scope) {
	const rule = "G32 internal is written by the packages internalBy lists alone";
	for (const owner of s.packages) {
		const listed = owner.manifest.internalBy;
		if (listed === undefined) continue;
		if (!Array.isArray(listed) || !listed.every((name) => typeof name === "string")) {
			s.report(rule, owner.name, "internalBy is no list of package names");
			continue;
		}
		for (const name of new Set(listed.filter((name, i) => listed.indexOf(name) !== i))) {
			s.report(rule, owner.name, `internalBy names ${name} twice`);
		}
		// The owner too: it states `internal`, and writes none.
		const written = writtenIn(s, owner, s.packages);
		if (typeof written === "string") {
			s.report(rule, owner.name, `internalBy, but it ${written}`);
			continue;
		}
		for (const name of new Set(listed)) {
			if (!s.byName.has(name)) {
				s.report(rule, owner.name, `internalBy: ${name} is no workspace package`);
			} else if (!written.some((w) => w.pkg.name === name)) {
				s.report(rule, owner.name, `internalBy: ${name} writes no internal`);
			}
		}
		for (const w of written.filter((w) => !listed.includes(w.pkg.name))) {
			s.report(rule, `${w.pkg.name}/${w.file}:${w.line}`, "internal");
		}
	}
}
