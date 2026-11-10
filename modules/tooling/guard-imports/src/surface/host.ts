import ts from "typescript";

/** The options every program reading a surface is made with. */
export const options: ts.CompilerOptions = {
	target: ts.ScriptTarget.ES2022,
	module: ts.ModuleKind.NodeNext,
	moduleResolution: ts.ModuleResolutionKind.NodeNext,
	allowImportingTsExtensions: true,
	noEmit: true,
	strict: true,
	skipLibCheck: true,
	types: [],
};

const parsed = new Map<string, { readonly text: string; readonly file: ts.SourceFile }>();

/**
 * The host every program parses through: a file read again with the same text is not parsed again.
 * Every program shares `options`, so a reused file binds and takes its module format the same.
 */
export const host: ts.CompilerHost = {
	...ts.createCompilerHost(options),
	getSourceFile: (fileName, languageVersion) => {
		const text = ts.sys.readFile(fileName);
		if (text === undefined) return undefined;
		const kept = parsed.get(fileName);
		if (kept?.text === text) return kept.file;
		const file = ts.createSourceFile(fileName, text, languageVersion);
		parsed.set(fileName, { text, file });
		return file;
	},
};
