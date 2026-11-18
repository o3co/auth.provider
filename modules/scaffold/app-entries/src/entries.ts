import { type Declared, type Declaring, declaredEntries, type Shape } from "./declared.ts";
import { configFiles, filled, type KeysWritten, kernel, refusedPart } from "./start.ts";

/**
 * The app's entries besides `start`, each for an app that composes its package: the same modules,
 * built and never started, running what that package offers. The template's mark `entry` names it.
 * `subjects` is the part shared by the entries that read subjects: the guard read first, then the app
 * read and built, never started, and the subjects read from standard input.
 */
interface Row {
	readonly package: string;
	readonly script: string;
	readonly template: string;
	readonly fill: Readonly<Record<string, string>>;
}

const templates: Readonly<Record<Shape, string>> = {
	call: "call.ts.template",
	"settle-subjects": "settle-subjects.ts.template",
	"name-subjects": "name-subjects.ts.template",
};

/** A declared entry as its shape's template fills it: each answer written as JSON data, never spliced in raw. */
const rowOf = (entry: Declared): Row => ({
	package: entry.package,
	script: entry.script,
	template: templates[entry.shape],
	fill: {
		contract: entry.contract,
		member: entry.member,
		...(entry.answers
			? { answers: `[${entry.answers.map((a) => JSON.stringify(a)).join(", ")}]` }
			: {}),
	},
});

/**
 * The scripts and files of the entries the composed modules call for; `run` writes the command
 * that runs a file, as the project starts its app. `declaring` is what the composed packages
 * declare in their manifests' `appEntries`; a declaration that cannot be read is refused, naming
 * its package.
 */
export async function entriesOf(
	modules: readonly string[],
	importOf: (name: string) => string,
	run: (file: string) => string,
	keys?: KeysWritten,
	declaring: readonly Declaring[] = [],
) {
	const composed = declaring.filter((pkg) => modules.includes(pkg.name));
	const called = declaredEntries(composed).map(rowOf);
	const files: Record<string, string> = {};
	for (const row of called) {
		const fill = {
			...row.fill,
			kernel: importOf(kernel),
			configFiles: importOf(configFiles),
			entry: importOf(row.package),
			imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
			modules: modules.map((_, i) => `m${i}`).join(", "),
		};
		const shared = {
			...fill,
			refused: await refusedPart(keys),
			guard: await filled("guard.ts.part", {}),
			reads: modules.map((name) => `import("${importOf(name)}/module")`).join(", "),
		};
		files[fileOf(row)] = await filled(row.template, {
			...shared,
			subjects: await filled("subjects.ts.part", shared),
		});
	}
	const scripts = Object.fromEntries(called.map((row) => [row.script, run(fileOf(row))]));
	return { scripts, files };
}

const fileOf = (row: Row) => `src/${row.script}.ts`;
