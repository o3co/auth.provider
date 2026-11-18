import { namesPackages, writeDeployment } from "@mod/app-output";
import { assemblyFor } from "./assembly.ts";
import type { FullPlan } from "./contract.ts";

/** Writes the full template's app; `index` is the published release's, a test's where given. */
export async function generateFull(plan: FullPlan, index?: string): Promise<readonly string[]> {
	const add = plan.add ?? [];
	namesPackages(add);
	const { packages, combinations, warnings } = assemblyFor(plan, index);
	const modules = combinations.full(add);
	await writeDeployment(plan.target, modules, packages, {
		template: "full-readme.md",
		fill: {
			optIns: combinations
				.optIns()
				.filter((name) => !add.includes(name))
				.map((name) => `- \`${name}\``)
				.join("\n"),
		},
	});
	return warnings;
}
