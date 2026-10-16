import { resolve } from "node:path";
import { completed } from "@mod/combinations";
import { kernelConfig } from "@mod/kernel";
import { generateFull } from "./full.ts";
import { packagesFor } from "./packages.ts";
import { generatePattern, type PatternPlan } from "./pattern.ts";
import { fullName } from "./patterns/patterns.ts";
import {
	mainSource,
	manifestOf,
	namesPackages,
	vacant,
	withKernel,
	writeProject,
} from "./project.ts";

/** A project assembling the modules named. */
export interface ModulesPlan {
	readonly target: string;
	/** Package names whose `./module` the app assembles, in order; their default wirings and bridges come along. */
	readonly modules: readonly string[];
	/** When set, dependencies link to this workspace instead of a registry. */
	readonly workspace?: string;
	/** The package whose `./module` contributes the app's log sink. */
	readonly sink?: string;
}

/** A project from the full template: what `combinations` composes in full, with the features added (the pattern `full`). */
export interface FullPlan {
	readonly target: string;
	readonly template: "full";
	/** Features of the workspace to compose beside the template's, with their wirings and bridges. */
	readonly add?: readonly string[];
	readonly workspace?: string;
}

export type Plan = ModulesPlan | FullPlan | PatternPlan;

const defaultSink = "@mod/log-stdout";

export async function generate(given: Plan): Promise<void> {
	// One path, resolved once, is both checked and written to: `missing/..` must not pass as empty.
	const plan = { ...given, target: resolve(given.target) };
	if ("template" in plan) {
		if (plan.template !== fullName) return generatePattern(plan);
		if ("axes" in plan || "features" in plan) throw new Error("full takes no axes or groups");
		return generateFull({ ...plan, template: fullName });
	}
	const sink = plan.sink ?? defaultSink;
	namesPackages([...plan.modules, sink]);
	await vacant(plan.target);
	const asked = completed(plan.modules);
	// Without a sink, the app's log lines would go nowhere.
	const modules = asked.includes(sink) ? asked : [...asked, sink];
	const packages = packagesFor(plan);
	await writeProject(plan.target, {
		"package.json": manifestOf("node src/main.ts", packages.dependencies(withKernel(modules))),
		"src/main.ts": await mainSource(modules, packages.importOf),
		"config/application.conf": `${JSON.stringify(kernelConfig(), null, "\t")}\n`,
		".gitignore": "node_modules/\nconfig/local*.conf\n",
	});
}
