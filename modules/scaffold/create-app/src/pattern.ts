/** A pattern's project: what `combinations` composes from the pattern's selection and the operator's choice. */
import { namesPackages, writeDeployment } from "@mod/app-output";
import { composed } from "@mod/combinations";
import { packagesFor } from "./packages.ts";
import { auditReceiversLine, chosenLines } from "./patterns/chosen.ts";
import { type Choice, oneInstance, type Pattern, selectionOf } from "./patterns/pattern.ts";
import { cardOf, patternNamed } from "./patterns/patterns.ts";

export interface PatternPlan extends Choice {
	readonly target: string;
	/** The pattern's name. */
	readonly template: string;
	readonly workspace?: string;
}

/** Generates the pattern the plan names, or the one given (a test's). */
export async function generatePattern(
	plan: PatternPlan,
	pattern: Pattern = patternNamed(plan.template),
): Promise<void> {
	const selection = selectionOf(pattern, plan);
	namesPackages([
		...Object.values(selection.features).flat(),
		...Object.entries(selection.axes ?? {}).flat(),
		...(selection.add ?? []),
	]);
	const modules = composed(selection);
	const deployment = oneInstance(selection)
		? "`single`: the store is kept in this process, so the deployment runs as one instance."
		: "`single` for one instance, `multi` for several.";
	const card = await cardOf(pattern.name);
	await writeDeployment(plan.target, modules, packagesFor(plan), {
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
