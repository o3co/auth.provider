import { resolve } from "node:path";
import type ts from "typescript";
import { type Edge, edgesOf } from "./edges.ts";
import { lexicalFile, lexicalProgram } from "./program.ts";
import { type MemberRead, type Reference, referencesOf } from "./references.ts";

export type { Edge, EdgeBinding, EdgeForm, Specifier } from "./edges.ts";
export { loaderOf } from "./edges.ts";
export type { Binding, MemberRead, Reference, Role } from "./references.ts";
export { roleOf, valueWithTypeArguments } from "./references.ts";
export type { Target, Unresolved } from "./resolve.ts";
export { esmTarget, packageOf, realOf, requireTarget } from "./resolve.ts";

/** What a file says, as one lexical program read it. */
export interface FileFacts {
	readonly path: string;
	/** The file's syntax tree, parents set, for a reader that reads more than the facts. */
	readonly file: ts.SourceFile;
	/** The lexical program's checker: binds names within the file, never across files or to a lib. */
	readonly checker: ts.TypeChecker;
	readonly edges: readonly Edge[];
	readonly references: readonly Reference[];
	readonly members: readonly MemberRead[];
}

export interface LexicalAnalysis {
	/** The facts of a file the analysis was made over; refuses any other, and a kind it does not read. */
	factsOf(path: string): FileFacts;
}

/** One lexical program over these files, each file's facts read once and kept. */
export function lexicalAnalysis(paths: readonly string[]): LexicalAnalysis {
	// Every spelling of a path, given or asked, read as the one absolute path the program names.
	const read = paths.filter(lexicalFile).map((path) => resolve(path));
	let program: ts.Program | undefined;
	const kept = new Map<string, FileFacts>();
	return {
		factsOf(asked) {
			const path = resolve(asked);
			const known = kept.get(path);
			if (known) return known;
			if (!lexicalFile(path)) throw new Error(`${path}: not a file a lexical program reads`);
			program ??= lexicalProgram(read);
			const file = program.getSourceFile(path);
			if (file === undefined) throw new Error(`${path}: not among the files analysed`);
			const checker = program.getTypeChecker();
			const edges = edgesOf(file, checker);
			const facts = { path, file, checker, edges, ...referencesOf(file, checker, edges) };
			kept.set(path, facts);
			return facts;
		},
	};
}
