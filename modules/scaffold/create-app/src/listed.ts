/** A listed app's project: the modules listed with what they need to run, written as a pattern's is. */
import { writeDeployment } from "@mod/app-output";
import { assemblyFor, type OutsidePlan } from "./assembly.ts";

/** Writes the app of `listed`, with what they need to run and the sink, into the plan's target; `index` as `generateFull` takes it. */
export async function generateListed(
	plan: { readonly target: string; readonly workspace?: string; readonly outside?: OutsidePlan },
	listed: readonly string[],
	sink: string,
	index?: string,
): Promise<void> {
	const { packages, combinations } = assemblyFor(plan, index);
	const asked = combinations.needed(listed);
	// Without a sink, the app's log lines would go nowhere.
	const modules = asked.includes(sink) ? asked : [...asked, sink];
	await writeDeployment(plan.target, modules, packages, {
		template: "listed-readme.md",
		fill: { listed: listed.map((name) => `\`${name}\``).join(", ") },
	});
}
