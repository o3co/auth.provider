import { readFileSync } from "node:fs";
import ts from "typescript";

/** The lexical program's options: no lib, nothing resolved, every file a module of its own. */
const options: ts.CompilerOptions = {
	noLib: true,
	noResolve: true,
	types: [],
	allowJs: true,
	target: ts.ScriptTarget.Latest,
	module: ts.ModuleKind.ESNext,
	// A file without an import or export is still a module: no script's globals reach another file.
	moduleDetection: ts.ModuleDetectionKind.Force,
};

/** The files a lexical program reads, as guard scans them: `.ts` (declaration files too) and `.mjs`; JSX, `.cts`, `.cjs` and `.mts` are not supported. */
export const lexicalFile = (path: string) => path.endsWith(".ts") || path.endsWith(".mjs");

/** One lexical program over these files: its host reads them alone and resolves nothing. */
export function lexicalProgram(paths: readonly string[]): ts.Program {
	const roots = new Set(paths);
	const read = (name: string) => (roots.has(name) ? readFileSync(name, "utf8") : undefined);
	const host: ts.CompilerHost = {
		getSourceFile: (name, version) => {
			const text = read(name);
			if (text === undefined) return undefined;
			const kind = name.endsWith(".mjs") ? ts.ScriptKind.JS : ts.ScriptKind.TS;
			return ts.createSourceFile(name, text, version, true, kind);
		},
		getDefaultLibFileName: () => "lib.d.ts",
		writeFile: () => undefined,
		getCurrentDirectory: () => "/",
		getCanonicalFileName: (name) => name,
		useCaseSensitiveFileNames: () => true,
		getNewLine: () => "\n",
		fileExists: (name) => roots.has(name),
		readFile: read,
		directoryExists: () => false,
		getDirectories: () => [],
		resolveModuleNameLiterals: (literals) => literals.map(() => ({ resolvedModule: undefined })),
		resolveTypeReferenceDirectiveReferences: (references) =>
			references.map(() => ({ resolvedTypeReferenceDirective: undefined })),
	};
	return ts.createProgram({ rootNames: [...roots], options, host });
}
