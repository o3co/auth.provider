import { spawnSync } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ClientPlanDefinition } from "./client-plan/client-plan.ts";
import type { PlanDefinition } from "./harness/harness.ts";
import { reclaimOrphans } from "./orphans/orphans.ts";

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

/** The relying party plans the harness drives itself, each one evidence run of its own. */
export const clientPlans = {
	rp: {
		name: "rp",
		suitePlan: "oidcc-client-test-plan",
		variant: {
			client_auth_type: "client_secret_basic",
			response_type: "code",
			response_mode: "default",
			client_registration: "static_client",
			request_type: "plain_http_request",
		},
		configuration: "rp.json",
		run: [
			"oidcc-client-test",
			"oidcc-client-test-client-secret-basic",
			"oidcc-client-test-scope-userinfo-claims",
			"oidcc-client-test-kid-absent-single-jwks",
			"oidcc-client-test-kid-absent-multiple-jwks",
			"oidcc-client-test-idtoken-sig-rs256",
			"oidcc-client-test-userinfo-bearer-header",
			"oidcc-client-test-aggregated-claims",
			"oidcc-client-test-discovery-openid-config",
			"oidcc-client-test-discovery-jwks-uri-keys",
			"oidcc-client-test-nonce-invalid",
			"oidcc-client-test-missing-iat",
			"oidcc-client-test-missing-aud",
			"oidcc-client-test-invalid-aud",
			"oidcc-client-test-missing-sub",
			"oidcc-client-test-invalid-sig-rs256",
			"oidcc-client-test-invalid-sig-hs256",
			"oidcc-client-test-invalid-sig-es256",
			"oidcc-client-test-invalid-iss",
			"oidcc-client-test-userinfo-invalid-sub",
			"oidcc-client-test-discovery-issuer-mismatch",
		],
		// The suite ends these on the app's first reads: the configuration at its start, the keys at
		// a login's id_token; any request after fails them.
		bootOnly: ["oidcc-client-test-discovery-openid-config"],
		withoutUserinfo: ["oidcc-client-test-discovery-jwks-uri-keys"],
		// What the provider does not offer: each has a skip entry naming why.
		notRun: [
			"oidcc-client-test-userinfo-bearer-body",
			"oidcc-client-test-distributed-claims",
			"oidcc-client-test-userinfo-signed",
			"oidcc-client-test-idtoken-sig-none",
			"oidcc-client-test-discovery-webfinger-acct",
			"oidcc-client-test-discovery-webfinger-url",
			"oidcc-client-test-signing-key-rotation",
			"oidcc-client-test-signing-key-rotation-just-before-signing",
		],
	},
} as const satisfies Record<string, ClientPlanDefinition>;

/** The runs the package's evidence comes from, as `spec-checklist` lists the runs a CI run must report: one job of the kind `oidf-plan` per plan, a gate run. */
export const evidenceRuns = [...Object.keys(plans), ...Object.keys(clientPlans)].map((name) => ({
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
	const known = [...Object.keys(plans), ...Object.keys(clientPlans)];
	const unknown = names.filter((n) => !known.includes(n));
	if (unknown.length > 0)
		throw new Error(`no plan ${unknown.join(", ")}: the plans are ${known.join(", ")}`);
	return (names.length === 0 ? known : names).map((run) => ({
		args: [
			"exec",
			"vitest",
			"run",
			"--config",
			run in clientPlans ? "vitest.rp.config.ts" : "vitest.config.ts",
			`runs/${run}.test.ts`,
		],
		run,
	}));
}

/** Where the plans keep their records: `named` where given, a directory made for them otherwise. */
export async function recordsOf(
	named: string | undefined,
): Promise<{ readonly dir: string; readonly made: boolean }> {
	if (named !== undefined) return { dir: named, made: false };
	return { dir: await mkdtemp(join(tmpdir(), "interop-oidf-records-")), made: true };
}

if (import.meta.main) {
	const [command, ...names] = process.argv.slice(2);
	if (command === "evidence-runs") console.log(JSON.stringify(evidenceRuns));
	else if (command === "plan") {
		const commands = planCommands(names);
		// Every plan's records in one directory, made where none is named: a run killed before its
		// stops still has its suite's logs kept, somewhere told.
		const records = await recordsOf(process.env.OIDF_ARTIFACTS_DIR);
		if (records.made) console.error(`the plans' records are kept in ${records.dir}`);
		// One vitest for each plan: each its own report, under its own run's name.
		for (const { args, run } of commands) {
			const ran = spawnSync("pnpm", args, {
				cwd: join(import.meta.dirname, ".."),
				stdio: "inherit",
				env: { ...process.env, SPEC_EVIDENCE_RUN: run, OIDF_ARTIFACTS_DIR: records.dir },
			});
			if (ran.status !== 0) process.exitCode = ran.status ?? 1;
			// A plan's run killed before its stops (cancelled, or a worker that died) leaves its suite on the
			// fixed ports; it is taken down here, its logs kept, and the plan fails for it.
			const reclaimed = await reclaimOrphans(undefined, join(records.dir, run, "reclaimed"));
			if (reclaimed.length > 0) {
				console.error(`${run}: took down the suite its run left behind (${reclaimed.join(", ")})`);
				process.exitCode = 1;
			}
		}
	} else console.error(`usage: evidence-runs | plan [${Object.keys(plans).join("|")}]...`);
}
