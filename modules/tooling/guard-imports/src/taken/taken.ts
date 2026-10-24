import { join } from "node:path";
import ts from "typescript";
import { valuesTaken } from "../rules.ts";
import type { Scope } from "../scope.ts";
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

/**
 * G31: a contract its owner's manifest declares `takenBy` is imported, in shipped code, by the
 * packages it names alone; and the declaration names the modules of the kernel `takenBy` the
 * contract itself declares, no more and no fewer.
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
		for (const [name, takers] of Object.entries(declared)) {
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
			for (const path of shipped(s, p)) {
				const taken = valuesTaken(s.factsOf(p, path.slice(p.dir.length + 1)), owner.name);
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
