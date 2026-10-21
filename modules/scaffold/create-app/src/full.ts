import { namesPackages, writeDeployment } from "@mod/app-output";
import { full, optIns } from "@mod/combinations";
import type { FullPlan } from "./contract.ts";
import { packagesFor } from "./packages.ts";

export async function generateFull(plan: FullPlan): Promise<void> {
	const add = plan.add ?? [];
	namesPackages(add);
	const modules = full(add);
	await writeDeployment(plan.target, modules, packagesFor(plan), {
		template: "full-readme.md",
		fill: {
			optIns: optIns()
				.filter((name) => !add.includes(name))
				.map((name) => `- \`${name}\``)
				.join("\n"),
		},
	});
}
