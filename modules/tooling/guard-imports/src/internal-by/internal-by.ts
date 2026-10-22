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

/** The name an object literal's property is written under, a computed string key included. */
const nameOf = (property: ts.ObjectLiteralElementLike) => {
	const name = property.name;
	if (name === undefined) return undefined;
	if (ts.isComputedPropertyName(name)) {
		return ts.isStringLiteralLike(name.expression) ? name.expression.text : undefined;
	}
	return ts.isIdentifier(name) || ts.isStringLiteralLike(name) ? name.text : undefined;
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
	const contract = program.getSourceFile(ownerEntry);
	const narrower = contract?.statements.find(
		(st): st is ts.InterfaceDeclaration =>
			ts.isInterfaceDeclaration(st) && st.name.text === "Narrower",
	);
	const property = narrower && checker.getTypeAtLocation(narrower).getProperty("internal");
	if (narrower === undefined || property === undefined) return "exports no Narrower with internal";
	const wanted = checker.getNonNullableType(checker.getTypeOfSymbolAtLocation(property, narrower));
	const written: Written[] = [];
	for (const { p, path, file } of files) {
		const source = program.getSourceFile(path);
		if (!source) continue;
		const visit = (node: ts.Node): void => {
			if (ts.isObjectLiteralExpression(node)) {
				for (const element of node.properties) {
					if (nameOf(element) !== "internal") continue;
					const value = ts.isPropertyAssignment(element)
						? element.initializer
						: ts.isShorthandPropertyAssignment(element)
							? element.name
							: undefined;
					if (value === undefined) continue;
					const type = checker.getNonNullableType(checker.getTypeAtLocation(value));
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
		const others = s.packages.filter((p) => p !== owner);
		const written = writtenIn(s, owner, others);
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
