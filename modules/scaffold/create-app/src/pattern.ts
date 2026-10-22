/** A pattern's project: what `combinations` composes from the pattern's selection and the operator's choice. */
import { namesPackages, writeDeployment } from "@mod/app-output";
import { assemblyFor, type OutsidePlan } from "./assembly.ts";
import { auditReceiversLine, chosenLines } from "./patterns/chosen.ts";
import { type Choice, oneInstance, type Pattern, selectionOf } from "./patterns/pattern.ts";
import { cardOf, patternNamed } from "./patterns/patterns.ts";

export interface PatternPlan extends Choice {
	readonly target: string;
	/** The pattern's name. */
	readonly template: string;
	readonly workspace?: string;
	readonly outside?: OutsidePlan;
}

/** Generates the pattern the plan names, or the one given (a test's); `index` as `generateFull` takes it. */
export async function generatePattern(
	plan: PatternPlan,
	pattern: Pattern = patternNamed(plan.template),
	index?: string,
): Promise<void> {
	const selection = selectionOf(pattern, plan);
	namesPackages([
		...Object.values(selection.features).flat(),
		...Object.entries(selection.axes ?? {}).flat(),
		...(selection.add ?? []),
	]);
	const { packages, combinations } = assemblyFor(plan, index);
	const modules = combinations.composed(selection);
	const deployment = oneInstance(selection)
		? "`single`: the store is kept in this process, so the deployment runs as one instance."
		: "`single` for one instance, `multi` for several.";
	const card = await cardOf(pattern.name);
	await writeDeployment(plan.target, modules, packages, {
		template: "pattern-readme.md",
		fill: {
			name: pattern.name,
			use: pattern.use,
			card,
			chosen: chosenLines(modules).join("\n"),
			receivers: auditReceiversLine(modules),
			deployment,
		},
	});
}
