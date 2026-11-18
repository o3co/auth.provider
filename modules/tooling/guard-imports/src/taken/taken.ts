import { join } from "node:path";
import ts from "typescript";
import type { FileFacts } from "../facts/facts.ts";
import { valuesTaken } from "../rules.ts";
import type { Scope } from "../scope/scope.ts";
import { parse } from "../source.ts";
import type { Pkg } from "../workspace.ts";

const isStrings = (value: unknown): value is string[] =>
	Array.isArray(value) && value.every((item) => typeof item === "string");

/** A package's shipped sources, by path. */
const shipped = (s: Scope, p: Pkg) =>
	s
		.sources(p)
		.filter((file) => !s.isTest(file))
		.map((file) => join(p.dir, file));

/** Each contract a package exports whose kernel `contract` call declares `takenBy`, by its exported name: the module names it gives. */
function takenInCode(s: Scope, p: Pkg): Map<string, string[]> {
	const found = new Map<string, string[]>();
	for (const path of shipped(s, p)) {
		for (const statement of parse(path).statements) {
			if (!ts.isVariableStatement(statement)) continue;
			const exported = statement.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
			if (!exported) continue;
			for (const declaration of statement.declarationList.declarations) {
				const call = declaration.initializer;
				if (!ts.isIdentifier(declaration.name) || !call || !ts.isCallExpression(call)) continue;
				if (!ts.isIdentifier(call.expression) || call.expression.text !== "contract") continue;
				const options = call.arguments[1];
				if (!options || !ts.isObjectLiteralExpression(options)) continue;
				for (const property of options.properties) {
					if (!ts.isPropertyAssignment(property) || property.name.getText() !== "takenBy") continue;
					const list = property.initializer;
					if (!ts.isArrayLiteralExpression(list)) continue;
					found.set(
						declaration.name.text,
						list.elements.filter(ts.isStringLiteral).map((element) => element.text),
					);
				}
			}
		}
	}
	return found;
}

/** The name a package's shipped code gives its module in a `defineModule` call; none without one. */
function moduleNameOf(s: Scope, p: Pkg): string | undefined {
	for (const path of shipped(s, p)) {
		let name: string | undefined;
		const visit = (node: ts.Node): void => {
			if (name !== undefined) return;
			if (
				ts.isCallExpression(node) &&
				ts.isIdentifier(node.expression) &&
				node.expression.text === "defineModule"
			) {
				const options = node.arguments[0];
				if (options && ts.isObjectLiteralExpression(options)) {
					for (const property of options.properties) {
						if (
							ts.isPropertyAssignment(property) &&
							property.name.getText() === "name" &&
							ts.isStringLiteral(property.initializer)
						) {
							name = property.initializer.text;
						}
					}
				}
			}
			ts.forEachChild(node, visit);
		};
		visit(parse(path));
		if (name !== undefined) return name;
	}
	return undefined;
}

/** An expression seen through parentheses and type assertions. */
function bare(node: ts.Expression): ts.Expression {
	let at = node;
	while (
		ts.isParenthesizedExpression(at) ||
		ts.isAsExpression(at) ||
		ts.isSatisfiesExpression(at) ||
		ts.isNonNullExpression(at) ||
		ts.isTypeAssertionExpression(at)
	) {
		at = at.expression;
	}
	return at;
}

/** A member read by a name written out: `o.name` or `o["name"]`. */
function memberOf(node: ts.Expression): { object: ts.Expression; name: string } | undefined {
	if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.name)) {
		return { object: node.expression, name: node.name.text };
	}
	if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(node.argumentExpression)) {
		return { object: node.expression, name: node.argumentExpression.text };
	}
	return undefined;
}

/** Each name a declaration binds, through object and array patterns. */
function boundNames(name: ts.BindingName): ts.Identifier[] {
	if (ts.isIdentifier(name)) return [name];
	return name.elements.flatMap((element) =>
		ts.isOmittedExpression(element) ? [] : boundNames(element.name),
	);
}

/**
 * What a file imports from `from` as a value and exports again from itself, by the name it took:
 * `export { x }`, under an alias, `export default x`, `export const y = x`, or through a top-level
 * re-binding (`const y = x`) exported so; `*` for a namespace import exported whole. A member of a
 * namespace import read by a name written out (`ns.x`, `ns["x"]`, `const { x } = ns`) is that
 * member. Lexical: a value put in an object, an array or a call, a computed member or key, a rest
 * element or a spread, or one assigned later is not followed.
 */
function handedOn(facts: FileFacts, from: string): string[] {
	const imported = new Map<ts.Symbol, string>();
	for (const edge of facts.edges) {
		if (!edge.loads || edge.specifier.text !== from) continue;
		for (const binding of edge.bindings) {
			const symbol = binding.local && facts.checker.getSymbolAtLocation(binding.local);
			if (symbol === undefined || binding.typeOnly) continue;
			imported.set(symbol, binding.form === "namespace" ? "*" : binding.imported);
		}
	}
	if (imported.size === 0) return [];
	const symbolOf = (node: ts.Node) => facts.checker.getSymbolAtLocation(node);
	const takenAt = (node: ts.Expression | undefined): string | undefined => {
		if (node === undefined) return undefined;
		const at = bare(node);
		if (ts.isIdentifier(at)) {
			const symbol = symbolOf(at);
			return symbol && imported.get(symbol);
		}
		const member = memberOf(at);
		return member && takenAt(member.object) === "*" ? member.name : undefined;
	};
	const bind = (name: ts.Identifier, taken: string | undefined) => {
		const symbol = symbolOf(name);
		if (taken === undefined || symbol === undefined || imported.has(symbol)) return false;
		imported.set(symbol, taken);
		return true;
	};
	const statements = facts.file.statements;
	const declarations = statements
		.filter(ts.isVariableStatement)
		.flatMap((statement) => [...statement.declarationList.declarations]);
	for (let grew = true; grew; ) {
		grew = false;
		for (const declaration of declarations) {
			const taken = takenAt(declaration.initializer);
			if (ts.isIdentifier(declaration.name)) {
				grew = bind(declaration.name, taken) || grew;
			} else if (ts.isObjectBindingPattern(declaration.name) && taken === "*") {
				for (const element of declaration.name.elements) {
					const key = element.propertyName ?? element.name;
					if (element.dotDotDotToken || !ts.isIdentifier(element.name)) continue;
					if (!ts.isIdentifier(key) && !ts.isStringLiteralLike(key)) continue;
					grew = bind(element.name, key.text) || grew;
				}
			}
		}
	}
	const exported: (string | undefined)[] = [];
	for (const statement of statements) {
		if (ts.isExportAssignment(statement)) exported.push(takenAt(statement.expression));
		const clause = ts.isExportDeclaration(statement) ? statement : undefined;
		if (clause && !clause.moduleSpecifier && !clause.isTypeOnly && clause.exportClause) {
			if (ts.isNamedExports(clause.exportClause)) {
				for (const element of clause.exportClause.elements) {
					if (element.isTypeOnly) continue;
					const symbol = facts.checker.getExportSpecifierLocalTargetSymbol(element);
					exported.push(symbol && imported.get(symbol));
				}
			}
		}
		const marked = ts.isVariableStatement(statement)
			? ts.getModifiers(statement)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
			: false;
		if (marked && ts.isVariableStatement(statement)) {
			for (const declaration of statement.declarationList.declarations) {
				for (const name of boundNames(declaration.name)) {
					const symbol = symbolOf(name);
					exported.push(symbol && imported.get(symbol));
				}
			}
		}
	}
	return [...new Set(exported.filter((name) => name !== undefined))];
}

/** Whether a `takenBy` key names an entry of the owner (`./name`) rather than a contract. */
const isEntry = (key: string) => key.startsWith(".");
/** Whether a source file exports a type: a type or an interface, a type re-exported, `export *` or `export * as`. */
function exportsType(path: string): boolean {
	return parse(path).statements.some((statement) => {
		const exported = (
			ts.canHaveModifiers(statement) ? ts.getModifiers(statement) : undefined
		)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
		if (
			exported &&
			(ts.isTypeAliasDeclaration(statement) || ts.isInterfaceDeclaration(statement))
		) {
			return true;
		}
		if (!ts.isExportDeclaration(statement)) return false;
		const clause = statement.exportClause;
		return (
			statement.isTypeOnly ||
			clause === undefined ||
			ts.isNamespaceExport(clause) ||
			(ts.isNamedExports(clause) && clause.elements.some((element) => element.isTypeOnly))
		);
	});
}

/** The file the owner exports a kept entry from. */
const entryFile = (p: Pkg, key: string) =>
	join(p.dir, (p.manifest.exports as Record<string, string>)[key] as string);

/**
 * G31's branch for an entry: the owner's entry `key` is loaded, in shipped code, by the packages it
 * names alone, by any edge (an import, a re-export, `import()`, `require`), a type alone not counted;
 * and a package it names does not hand it on, by a re-export or by exporting again what it imported
 * (`handedOn`). The owner keeps the runtime half itself, so no
 * module and no kernel `takenBy` is asked for.
 */
function entryTaken(s: Scope, rule: string, owner: Pkg, key: string, takers: readonly string[]) {
	for (const taker of takers) {
		if (!s.byName.has(taker))
			s.report(rule, owner.name, `${key}: ${taker} is no workspace package`);
	}
	const specifier = `${owner.name}/${key.slice(2)}`;
	for (const p of s.packages) {
		if (p === owner) continue;
		for (const path of shipped(s, p)) {
			const file = path.slice(p.dir.length + 1);
			const edges = s.factsOf(p, file).edges.filter((e) => e.specifier.text === specifier);
			const where = `${p.name}/${file}`;
			if (!takers.includes(p.name)) {
				if (edges.some((e) => e.loads)) s.report(rule, where, `${key} of ${owner.name}`);
			} else if (
				edges.some((e) => e.form === "export-from" && e.loads) ||
				handedOn(s.factsOf(p, file), specifier).length > 0
			) {
				s.report(rule, where, `${key} of ${owner.name}: a taker does not hand it on`);
			}
		}
	}
}

/**
 * G31: a contract its owner's manifest declares `takenBy` is imported, in shipped code, by the
 * packages it names alone; and the declaration names the modules of the kernel `takenBy` the
 * contract itself declares, no more and no fewer. A key naming an entry is held by `entryTaken`.
 */
export function takenByRules(s: Scope) {
	const rule = "G31 a contract declared takenBy is imported by the packages it names alone";
	for (const owner of s.packages) {
		const declared = owner.manifest.takenBy;
		if (declared === undefined) continue;
		if (typeof declared !== "object" || declared === null || Array.isArray(declared)) {
			s.report(rule, owner.name, "takenBy is no map of contract names to packages");
			continue;
		}
		const inCode = takenInCode(s, owner);
		const allowed = new Map<string, readonly string[]>();
		const entries = s.takenEntries(owner);
		for (const [name, takers] of Object.entries(declared)) {
			if (isEntry(name)) {
				const why = entries.notKept.find(({ key }) => key === name)?.why;
				if (why !== undefined) s.report(rule, owner.name, `${name}: ${why}`);
				else if (exportsType(entryFile(owner, name))) {
					s.report(
						rule,
						owner.name,
						`${name}: an entry kept exports values alone, its types on \`.\``,
					);
				} else entryTaken(s, rule, owner, name, takers as string[]);
				continue;
			}
			if (!isStrings(takers)) {
				s.report(rule, owner.name, `${name}: takenBy names packages as a list of names`);
				continue;
			}
			allowed.set(name, takers);
			const modules: string[] = [];
			for (const taker of takers) {
				const q = s.byName.get(taker);
				const module = q && moduleNameOf(s, q);
				if (!q) s.report(rule, owner.name, `${name}: ${taker} is no workspace package`);
				else if (module === undefined) {
					s.report(rule, owner.name, `${name}: ${taker} has no module to take it`);
				} else modules.push(module);
			}
			if (modules.length !== takers.length) continue;
			const code = inCode.get(name);
			if (code === undefined) {
				s.report(rule, owner.name, `${name}: no contract of that name declares takenBy`);
			} else if ([...code].sort().join() !== [...modules].sort().join()) {
				const named = `takenBy in code names ${code.join(", ")}, the manifest ${modules.join(", ")}`;
				s.report(rule, owner.name, `${name}: ${named}`);
			}
		}
		for (const name of inCode.keys()) {
			if (!(name in declared)) {
				s.report(rule, owner.name, `${name}: takenBy in code, but not in the manifest`);
			}
		}
		for (const p of s.packages) {
			if (p === owner) continue;
			// An adapter of the owner imports its contracts to provide them; taking one is refused at assembly.
			// Handing one on is counted: a re-export, or exporting again what it imported (`handedOn`).
			const forms = s.ownerServed(p) === owner.name ? (["export-from"] as const) : undefined;
			for (const path of shipped(s, p)) {
				const facts = s.factsOf(p, path.slice(p.dir.length + 1));
				const taken = valuesTaken(facts, owner.name, forms);
				if (forms !== undefined) taken.push(...handedOn(facts, owner.name));
				for (const [name, takers] of allowed) {
					if (takers.includes(p.name)) continue;
					if (taken.includes(name) || taken.includes("*")) {
						s.report(rule, `${p.name}/${path.slice(p.dir.length + 1)}`, `${name} of ${owner.name}`);
					}
				}
			}
		}
	}
}
