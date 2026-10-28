import { configFiles, filled, kernel, refusedPart } from "../project.ts";

/**
 * The app's entries besides `start`, each for an app that composes its package: the same modules,
 * built and never started, running what that package offers. The template's mark `entry` names it;
 * a backfill's marks `contract` and `answers` name the contract it settles through and the answers
 * it counts, in the order its line tells them. `subjects` is the part shared by the entries that
 * read subjects: the guard read first, then the app read and built, never started, and the subjects
 * read from standard input.
 */
const entries: readonly {
	readonly script: string;
	readonly file: string;
	readonly template: string;
	readonly runs: string;
	readonly fill?: Readonly<Record<string, string>>;
}[] = [
	{ script: "reseal", file: "src/reseal.ts", template: "reseal.ts.template", runs: "@mod/seal" },
	{
		script: "witness-backfill",
		file: "src/witness-backfill.ts",
		template: "backfill.ts.template",
		runs: "@mod/mfa-witnessing",
		fill: {
			contract: "witnessBackfill",
			answers: '"marked", "held", "none", "unclaimed", "inconsistent"',
		},
	},
	{
		script: "passkey-backfill",
		file: "src/passkey-backfill.ts",
		template: "backfill.ts.template",
		runs: "@mod/passkey-witnessing",
		fill: {
			contract: "passkeyBackfill",
			answers: '"marked", "held", "none", "pending", "inconsistent"',
		},
	},
	{
		script: "unclaimed-factors",
		file: "src/unclaimed-factors.ts",
		template: "unclaimed-factors.ts.template",
		runs: "@mod/mfa-reset",
		fill: { contract: "resetCandidates" },
	},
];

/**
 * The scripts and files of the entries the composed modules call for; `run` writes the command
 * that runs a file, as the project starts its app.
 */
export async function entriesOf(
	modules: readonly string[],
	importOf: (name: string) => string,
	run: (file: string) => string,
) {
	const called = entries.filter((entry) => modules.includes(entry.runs));
	const files: Record<string, string> = {};
	for (const entry of called) {
		const fill = {
			...entry.fill,
			kernel: importOf(kernel),
			configFiles: importOf(configFiles),
			entry: importOf(entry.runs),
			imports: modules.map((name, i) => `import m${i} from "${importOf(name)}/module";`).join("\n"),
			modules: modules.map((_, i) => `m${i}`).join(", "),
		};
		const shared = {
			...fill,
			refused: await refusedPart(),
			guard: await filled("guard.ts.part", {}),
			reads: modules.map((name) => `import("${importOf(name)}/module")`).join(", "),
		};
		files[entry.file] = await filled(entry.template, {
			...shared,
			subjects: await filled("subjects.ts.part", shared),
		});
	}
	const scripts = Object.fromEntries(called.map((entry) => [entry.script, run(entry.file)]));
	return { scripts, files };
}
