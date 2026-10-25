import { join } from "node:path";
import { readChecklist } from "@mod/spec-checklist";
import type { TestContext } from "vitest";
import { differencesOf, readDifferences } from "../src/differences/differences.ts";
import { type Flow, libraries, libraryNamed } from "../src/libraries/libraries.ts";

/** The library this run is of, and whether it runs a flow first-class. */
export const library = libraryNamed(process.env.INTEROP_LIBRARY);
export const runs = (flow: Flow) => library.flows.includes(flow);

const checklist = readChecklist();
const differences = differencesOf(
	readDifferences(
		join(import.meta.dirname, "..", "known-differences.json"),
		{
			items: new Map(checklist.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const))),
			decisions: checklist.decisions,
		},
		libraries.map((l) => l.name),
	),
	library.name,
);

/** Runs a check; a failure a known difference names is skipped as excused, by its class. */
export async function excusable(context: TestContext, flow: Flow, check: () => Promise<void>) {
	try {
		await check();
	} catch (failure) {
		const known = differences.excusing(flow, context.task.name);
		if (!known) throw failure;
		context.skip(`excused: ${known.class}`);
	}
}

/** The known differences of these flows that no check of this file met. */
export const unmetOf = (flows: readonly Flow[]) =>
	differences.unmet().filter((d) => flows.includes(d.flow as Flow));
