import { join } from "node:path";
import { internalByRules } from "./internal-by/internal-by.ts";
import { declaredRecordRules } from "./recorded/recorded.ts";
import {
	axisRules,
	bridgeRules,
	cycles,
	dependencyRules,
	fileImportRules,
	helperRules,
	ownFileRules,
	wiringRules,
} from "./rules.ts";
import { type Rules, type Scope, scopeOf } from "./scope.ts";
import { type Surface, surfaceOf } from "./surface.ts";
import { takenByRules } from "./taken/taken.ts";
import type { Pkg } from "./workspace.ts";

export type {
	Binding,
	Edge,
	EdgeBinding,
	EdgeForm,
	FileFacts,
	MemberRead,
	Reference,
	Role,
	Specifier,
	Target,
	Unresolved,
} from "./facts/facts.ts";
export { type LexicalAnalysis, lexicalAnalysis } from "./facts/facts.ts";
export { budgetsAsTest, type Kinds, type Rules, type Scope, scopeOf } from "./scope.ts";
export { type ImportUse, importedNames, importsOf, packageOf, parse } from "./source.ts";
export type { Surface } from "./surface.ts";
export { type Pkg, readWorkspace } from "./workspace.ts";

/** A rule's finding: the rule by its id, the place, and what went over. */
export interface Violation {
	readonly rule: string;
	readonly where: string;
	readonly detail: string;
}

/** Each package's public surface, by name, read from its `.` entry. */
export function surfacesOf(packages: readonly Pkg[]): Map<string, Surface> {
	const surfaces = new Map<string, Surface>();
	for (const p of packages) {
		const entry = p.manifest.exports?.["."];
		if (entry) surfaces.set(p.name, surfaceOf(join(p.dir, entry), p.dir));
	}
	return surfaces;
}

/** Every import and dependency rule over the scope's packages, each reporting through the scope. */
export function importRules(s: Scope, surfaces: ReadonlyMap<string, Surface>): void {
	cycles(s);
	for (const p of s.packages) {
		dependencyRules(s, p);
		for (const file of s.sources(p)) {
			fileImportRules(s, p, file);
			ownFileRules(s, p, file);
		}
		helperRules(s, p, surfaces);
	}
	wiringRules(s);
	axisRules(s);
	bridgeRules(s, surfaces);
	declaredRecordRules(s);
	takenByRules(s);
	internalByRules(s);
}

/** The import and dependency rules over the workspace, as their findings. */
export function importViolations(packages: readonly Pkg[], rules: Rules): Violation[] {
	const violations: Violation[] = [];
	const s = scopeOf(packages, rules, (rule, where, detail) =>
		violations.push({ rule, where, detail }),
	);
	importRules(s, surfacesOf(packages));
	return violations;
}
