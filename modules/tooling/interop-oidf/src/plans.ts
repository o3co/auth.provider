import { spawnSync } from "node:child_process";
import { join } from "node:path";
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
	"rp-initiated-logout": {
		name: "rp-initiated-logout",
		suitePlan:
			"oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]",
		configuration: "logout.json",
		logout: "redirect",
	},
	"backchannel-logout": {
		name: "backchannel-logout",
		suitePlan:
			"oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]",
		configuration: "logout.json",
		logout: "backchannel",
	},
	"frontchannel-logout": {
		name: "frontchannel-logout",
		suitePlan:
			"oidcc-frontchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]",
		configuration: "logout.json",
		logout: "frontchannel",
	},
} as const satisfies Record<string, PlanDefinition>;

/** The runs the package's evidence comes from, as `spec-checklist` lists the runs a CI run must report: one job of the kind `oidf-plan` per plan, a gate run. */
export const evidenceRuns = Object.keys(plans).map((name) => ({
	entry: `@mod/interop-oidf#${name}`,
	kind: "oidf-plan",
	matrix: name,
	// Its tests name no item yet, so a release stops on each that failed, whatever it names.
	gate: true,
}));

/** The vitest each named plan runs in (every plan where none is named), on its own file, naming its evidence run. */
export function planCommands(
	names: readonly string[],
): { readonly args: string[]; readonly run: string }[] {
	const known = Object.keys(plans);
	const unknown = names.filter((n) => !known.includes(n));
	if (unknown.length > 0)
		throw new Error(`no plan ${unknown.join(", ")}: the plans are ${known.join(", ")}`);
	return (names.length === 0 ? known : names).map((run) => ({
		args: ["exec", "vitest", "run", "--config", "vitest.config.ts", `runs/${run}.test.ts`],
		run,
	}));
}

if (import.meta.main) {
	const [command, ...names] = process.argv.slice(2);
	if (command === "evidence-runs") console.log(JSON.stringify(evidenceRuns));
	else if (command === "plan") {
		// One vitest for each plan: each its own report, under its own run's name.
		for (const { args, run } of planCommands(names)) {
			const ran = spawnSync("pnpm", args, {
				cwd: join(import.meta.dirname, ".."),
				stdio: "inherit",
				env: { ...process.env, SPEC_EVIDENCE_RUN: run },
			});
			if (ran.status !== 0) process.exitCode = ran.status ?? 1;
		}
	} else console.error(`usage: evidence-runs | plan [${Object.keys(plans).join("|")}]...`);
}
