import type { PlanDefinition } from "./harness/harness.ts";

/** The OP plans the harness runs, each one evidence run of its own. */
export const plans = {
	basic: {
		name: "basic",
		suitePlan:
			"oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]",
		configuration: "op.json",
	},
	config: {
		name: "config",
		suitePlan: "oidcc-config-certification-test-plan",
		configuration: "op.json",
	},
} as const satisfies Record<string, PlanDefinition>;

/** The runs the package's evidence comes from, as `spec-checklist` lists the runs a CI run must report: one job of the kind `oidf-plan` per plan. */
export const evidenceRuns = Object.keys(plans).map((name) => ({
	entry: `@mod/interop-oidf#${name}`,
	kind: "oidf-plan",
	matrix: name,
}));

if (process.argv[2] === "evidence-runs") console.log(JSON.stringify(evidenceRuns));
