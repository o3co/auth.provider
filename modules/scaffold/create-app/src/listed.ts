/** A listed app's project: the modules listed with what they need to run, written as a pattern's is. */
import { writeDeployment } from "@mod/app-output";
import { assemblyFor, type OutsidePlan } from "./assembly.ts";
import { auditReceiversLine, chosenLines } from "./patterns/chosen.ts";

/** The store kept in memory: an app composing it runs as one instance. */
const memoryStore = "@mod/store";

/** Writes the app of `listed`, with what they need to run and the sink, into the plan's target; `index` as `generateFull` takes it. */
/** The modules that issue what must be revocable, and so refuse `tokens.revocation = unsupported`. */
const revocable = ["@mod/code-grant", "@mod/refresh", "@mod/session-tokens"];

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
	const chosen = chosenLines(modules);
	await writeDeployment(plan.target, modules, packages, {
		template: "listed-readme.md",
		fill: {
			listed: listed.map((name) => `\`${name}\``).join(", "),
			chosen:
				chosen.length === 0
					? ""
					: ["## Store, users, audit and mail", "", ...chosen, "", ""].join("\n"),
			decided: decidedLines(modules).join("\n"),
		},
	});
}

/** The values the operator decides, for the modules composed. */
function decidedLines(modules: readonly string[]): string[] {
	return [
		modules.includes(memoryStore)
			? "- `kernel.deployment`: `single`: the store is kept in this process, so the deployment runs as one instance; list `@mod/redis` to keep it in Redis and run several."
			: "- `kernel.deployment`: `single` for one instance, `multi` for several.",
		...(modules.includes("@mod/tokens")
			? [
					// Codes and refresh tokens must be revocable: their modules refuse `unsupported`.
					revocable.some((name) => modules.includes(name))
						? "- `tokens.revocation`: `denylist`, as this app issues codes or refresh tokens, which must be revocable."
						: "- `tokens.revocation`: `denylist`, or `unsupported` to answer revocation as unsupported.",
				]
			: []),
		...(modules.includes("@mod/audit")
			? [
					`- \`audit.receivers\`: the names of the audit receivers composed: ${auditReceiversLine(modules)}.`,
				]
			: []),
	];
}
