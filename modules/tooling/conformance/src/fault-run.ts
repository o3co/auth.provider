import type { Reporter } from "vitest/node";

/** A test module as vitest's reporter gives it, as far as a fault run reads it. */
interface Module {
	readonly moduleId: string;
	readonly children: {
		allTests(): Iterable<{ readonly name: string; result(): { readonly state: string } }>;
	};
}

/** Each test of a fault scene's file (`*.faults.case.ts`) that did not run: skipped or left todo. */
export function skippedFaultScenes(modules: readonly Module[]): string[] {
	return modules
		.filter((m) => /\.faults\.case\.ts$/.test(m.moduleId))
		.flatMap((m) =>
			[...m.children.allTests()]
				.filter((t) => t.result().state !== "passed" && t.result().state !== "failed")
				.map((t) => `${m.moduleId} > ${t.name}`),
		);
}

/**
 * Fails a fault run (`CONFORMANCE_FAULTS=1`) where any fault scene did not run, excused or not: a green
 * job with a skipped fault shows nothing. Elsewhere, such as a run without Docker on a laptop, it does nothing.
 */
export function faultRunReporter(env: NodeJS.ProcessEnv = process.env): Reporter {
	return {
		onTestRunEnd(modules) {
			if (env.CONFORMANCE_FAULTS !== "1") return;
			const skipped = skippedFaultScenes(modules as unknown as Module[]);
			if (skipped.length > 0)
				throw new Error(`fault scenes that did not run in a fault run:\n${skipped.join("\n")}`);
		},
	};
}

/** Whether this run is a fault run, where a fault scene that cannot run fails rather than skips. */
export const faultRun = (env: NodeJS.ProcessEnv = process.env) => env.CONFORMANCE_FAULTS === "1";
