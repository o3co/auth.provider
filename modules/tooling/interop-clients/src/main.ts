import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { libraries, libraryNamed } from "./libraries/libraries.ts";

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

if (import.meta.main) {
	const [command, name] = process.argv.slice(2);
	if (command === "--evidence-runs") console.log(JSON.stringify(evidenceRuns()));
	else if (command === "library" && name) process.exitCode = runLibrary(name);
	else {
		console.error(`usage: --evidence-runs | library <${libraries.map((l) => l.name).join("|")}>`);
		process.exitCode = 2;
	}
}
