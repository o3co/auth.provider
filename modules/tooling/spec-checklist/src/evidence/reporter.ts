import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import type { Reporter, TestCase, TestModule, Vitest } from "vitest/node";

/** One vitest run's results, named by what ran them. */
export interface EvidenceReport {
	readonly identity: {
		readonly commit: string;
		readonly run: string;
		readonly attempt: number;
		readonly job: string;
		/** The run it stands for: `unit`, `integration`, a package, `<package>@<pattern>` or `<package>#<run>`. */
		readonly entry: string;
		readonly target: "new" | "legacy";
	};
	readonly tests: readonly EvidenceTest[];
	/** Errors no test owns; any makes the run's tests unproven. */
	readonly errors: number;
}

export interface EvidenceTest {
	/** The file, relative to the repository's root. */
	readonly file: string;
	/** Its suites' names and its own, outermost first; none for a file that failed to load. */
	readonly names: readonly string[];
	readonly state: "passed" | "failed" | "skipped" | "pending";
	readonly note?: string;
}

const repoRoot = join(import.meta.dirname, "..", "..", "..", "..", "..");

/** The run a vitest config stands for, from its file, the package beside it and the environment. */
export function entryOf(
	configFile: string,
	pkg: string | undefined,
	env: Readonly<Record<string, string | undefined>>,
	rootDir = repoRoot,
): string {
	const file = relative(rootDir, configFile);
	if (file === "vitest.config.ts") return "unit";
	if (file === "vitest.integration.config.ts") return "integration";
	const pattern = env.CONFORMANCE_PATTERN ? `@${env.CONFORMANCE_PATTERN}` : "";
	const run = env.SPEC_EVIDENCE_RUN ? `#${env.SPEC_EVIDENCE_RUN}` : "";
	return `${pkg ?? relative(rootDir, dirname(configFile))}${pattern}${run}`;
}

const packageOf = (root: string): string | undefined => {
	try {
		return JSON.parse(readFileSync(join(root, "package.json"), "utf8")).name;
	} catch {
		return undefined;
	}
};

const namesOf = (test: TestCase): string[] => {
	const names = [test.name];
	for (let at = test.parent; at.type === "suite"; at = at.parent) names.unshift(at.name);
	return names;
};

/** Whether a suite the test is in, or its file, failed outside its tests, such as in a hook. */
const suiteFailed = (test: TestCase): boolean => {
	let at = test.parent;
	for (; at.type === "suite"; at = at.parent) if (at.errors().length > 0) return true;
	return at.errors().length > 0;
};

function testsOf(module: TestModule): EvidenceTest[] {
	const file = relative(repoRoot, module.moduleId);
	const tests: EvidenceTest[] = [...module.children.allTests()].map((t) => {
		const result = t.result();
		// A test that passed in a suite that failed proves nothing: its hook may not have run its part.
		const state = suiteFailed(t) ? "failed" : result.state;
		const note = state === "skipped" && result.state === "skipped" ? result.note : undefined;
		return { file, names: namesOf(t), state, ...(note ? { note } : {}) };
	});
	return module.errors().length > 0 ? [...tests, { file, names: [], state: "failed" }] : tests;
}

/**
 * Writes each run's results to `SPEC_EVIDENCE_DIR`, named by the commit, the run, the job and the
 * entry, so a later step can tell which expected runs passed; without the directory, does nothing.
 */
export function evidenceReporter(env: NodeJS.ProcessEnv = process.env): Reporter {
	let vitest: Vitest | undefined;
	return {
		onInit(v) {
			vitest = v;
		},
		onTestRunEnd(modules, errors) {
			const dir = env.SPEC_EVIDENCE_DIR;
			if (!dir || !vitest) return;
			// The config file as vite resolved it: vitest leaves its own `config` unset where it found the file itself.
			const config = String(vitest.vite.config.configFile ?? vitest.config.config ?? "");
			const entry = entryOf(config, packageOf(dirname(config)), env);
			const target = env.CONFORMANCE_TARGET === "legacy" ? "legacy" : "new";
			const report: EvidenceReport = {
				identity: {
					commit: env.GITHUB_SHA ?? "local",
					run: env.GITHUB_RUN_ID ?? "local",
					attempt: Number(env.GITHUB_RUN_ATTEMPT ?? 1),
					job: env.GITHUB_JOB ?? "local",
					entry,
					target,
				},
				tests: modules.flatMap(testsOf),
				errors: errors.length,
			};
			mkdirSync(dir, { recursive: true });
			const name = `${entry}-${target}-${process.pid}`.replace(/[^\w@#.+-]/g, "_");
			writeFileSync(join(dir, `${name}.json`), JSON.stringify(report));
		},
	};
}
