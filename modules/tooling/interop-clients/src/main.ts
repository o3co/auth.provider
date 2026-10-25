import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { libraries, libraryNamed } from "./libraries/libraries.ts";
import { jarsIn, pinProblems, pinsText } from "./pins/pins.ts";

const packageDir = join(import.meta.dirname, "..");

/** Each library's run, as `spec-checklist` lists a CI run's runs: a library job's, its matrix the library. */
const evidenceRuns = () =>
	libraries.map((l) => ({
		entry: `@mod/interop-clients#${l.name}`,
		kind: "library",
		matrix: l.name,
	}));

/** Builds a library's adapter, then runs the flow tests with it; answers the tests' exit status. */
function runLibrary(name: string): number {
	const library = libraryNamed(name);
	for (const [command = "", ...args] of library.build) {
		const built = spawnSync(command, args, { cwd: packageDir, stdio: "inherit" });
		if (built.status !== 0) {
			console.error(`${name}: building the adapter failed (${command} ${args.join(" ")})`);
			return built.status ?? 1;
		}
	}
	const ran = spawnSync("pnpm", ["exec", "vitest", "run", "--config", "vitest.config.ts"], {
		cwd: packageDir,
		stdio: "inherit",
		env: { ...process.env, INTEROP_LIBRARY: name, SPEC_EVIDENCE_RUN: name },
	});
	return ran.status ?? 1;
}

/** An adapter's runtime jars (`target/deps`) against its `jars.sha256`; any difference fails, naming each. */
function verifyJars(adapter: string): number {
	const dir = join(packageDir, adapter);
	const problems = pinProblems(
		jarsIn(join(dir, "target", "deps")),
		readFileSync(join(dir, "jars.sha256"), "utf8"),
	);
	for (const p of problems) console.error(`${adapter}: ${p}`);
	return problems.length === 0 ? 0 : 1;
}

if (import.meta.main) {
	const [command, name] = process.argv.slice(2);
	if (command === "--evidence-runs") console.log(JSON.stringify(evidenceRuns()));
	else if (command === "library" && name) process.exitCode = runLibrary(name);
	else if (command === "verify-jars" && name) process.exitCode = verifyJars(name);
	// After a version bump, reviewed: the jars as they are now become the pins.
	else if (command === "pin-jars" && name)
		writeFileSync(
			join(packageDir, name, "jars.sha256"),
			pinsText(jarsIn(join(packageDir, name, "target", "deps"))),
		);
	else {
		console.error(
			`usage: --evidence-runs | library <${libraries.map((l) => l.name).join("|")}> | verify-jars <adapter dir> | pin-jars <adapter dir>`,
		);
		process.exitCode = 2;
	}
}
