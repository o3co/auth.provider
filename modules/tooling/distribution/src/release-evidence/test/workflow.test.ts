import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { conditionOf, inputOf, type RunContext } from "../../workflow-caches/test/expression.ts";

/** The release workflow, read as GitHub reads it. */
const workflow = parse(
	readFileSync(
		join(
			import.meta.dirname,
			"..",
			"..",
			"..",
			"..",
			"..",
			"..",
			".github",
			"workflows",
			"release.yml",
		),
		"utf8",
	),
) as {
	readonly jobs: Record<
		string,
		{
			readonly needs?: string | readonly string[];
			readonly if?: string;
			readonly environment?: string;
			readonly env?: Record<string, string>;
			readonly permissions?: Record<string, string>;
			readonly steps?: readonly {
				readonly id?: string;
				readonly name?: string;
				readonly if?: string;
				readonly uses?: string;
				readonly run?: string;
				readonly env?: Record<string, string>;
				readonly with?: Record<string, unknown>;
			}[];
		}
	>;
};
const evidence = workflow.jobs.evidence;

it("gives the evidence job only what reading another run's evidence takes, and no other job the runs to read", () => {
	expect(evidence?.permissions).toEqual({ contents: "read", actions: "read" });
	const reading = Object.entries(workflow.jobs).filter(
		([, job]) => job.permissions?.actions !== undefined,
	);
	expect(reading.map(([name]) => name)).toEqual(["evidence"]);
});

it("keeps no credential in the evidence job's checkout, and fetches main's history for the judge", () => {
	const checkout = evidence?.steps?.find((s) => s.uses?.startsWith("actions/checkout@"));
	expect(checkout?.with).toMatchObject({ "persist-credentials": false, "fetch-depth": 0 });
});

it("gives the token to fetching alone, before anything is installed, and judges holding none", () => {
	const steps = evidence?.steps ?? [];
	const holding = steps.filter(
		(s) => s.env?.GH_TOKEN !== undefined || s.env?.GITHUB_TOKEN !== undefined,
	);
	expect(holding.map((s) => s.run)).toEqual([
		expect.stringContaining("src/release-evidence/fetch.ts"),
	]);
	const fetchAt = steps.findIndex((s) => s.run?.includes("release-evidence/fetch.ts"));
	const installs = steps.flatMap((s, i) => (s.run?.includes("pnpm install") ? [i] : []));
	const judgeAt = steps.findIndex((s) => s.run?.includes("release-evidence/judge.ts"));
	expect(installs.length).toBeGreaterThan(0);
	for (const i of installs) {
		expect(i).toBeGreaterThan(fetchAt);
		expect(i).toBeLessThan(judgeAt);
		expect(steps[i]?.run).toContain("--ignore-scripts");
	}
});

it("keeps the evidence for publish, a re-run of all jobs writing over the one an earlier attempt kept", () => {
	const upload = evidence?.steps?.find((s) => s.uses?.startsWith("actions/upload-artifact@"));
	expect(upload?.with).toMatchObject({ name: "release-evidence", overwrite: true });
	const needs = workflow.jobs.publish?.needs;
	expect(typeof needs === "string" ? [needs] : needs).toContain("evidence");
});

describe("the routes a release's evidence may take", () => {
	type Needs = NonNullable<RunContext["needs"]>;
	const run = (needs: Needs, over: Partial<RunContext> = {}): RunContext => ({
		event_name: "push",
		ref: "refs/tags/v1.0.1",
		ref_name: "v1.0.1",
		base_ref: "",
		cancelled: false,
		needs,
		...over,
	});
	const done = { result: "success" };
	const routed = (route: string, result = "success") => ({
		result,
		outputs: { route, evidence: "11" },
	});
	const secured = (result: string) => ({ result, outputs: { evidence: "22" } });
	const publishes = (needs: Needs, over: Partial<RunContext> = {}) =>
		conditionOf(workflow.jobs.publish?.if, run(needs, over));

	it("publishes with exactly one route's evidence taken, the pack and the lists made", () => {
		const base = { pack: done, sbom: done };
		expect(
			publishes({ ...base, evidence: routed("public"), "evidence-security": secured("skipped") }),
		).toBe(true);
		expect(
			publishes({ ...base, evidence: routed("security"), "evidence-security": secured("success") }),
		).toBe(true);
		for (const needs of [
			{ ...base, evidence: routed("security"), "evidence-security": secured("failure") },
			{ ...base, evidence: routed("security"), "evidence-security": secured("cancelled") },
			{ ...base, evidence: routed("security"), "evidence-security": secured("skipped") },
			{ ...base, evidence: routed("public"), "evidence-security": secured("success") },
			{ ...base, evidence: routed("", "failure"), "evidence-security": secured("skipped") },
			{ ...base, evidence: routed("public", "failure"), "evidence-security": secured("skipped") },
			{
				pack: { result: "failure" },
				sbom: done,
				evidence: routed("public"),
				"evidence-security": secured("skipped"),
			},
			{
				pack: done,
				sbom: { result: "skipped" },
				evidence: routed("public"),
				"evidence-security": secured("skipped"),
			},
		]) {
			expect(publishes(needs)).toBe(false);
		}
		expect(
			publishes(
				{ ...base, evidence: routed("public"), "evidence-security": secured("skipped") },
				{ cancelled: true },
			),
		).toBe(false);
	});

	it("takes the evidence of the route taken, by its job's artifact id", () => {
		const take = workflow.jobs.publish?.steps?.find(
			(s) => s.name === "Take the evidence of the tested tree",
		);
		const id = (needs: Needs) => inputOf(take?.with?.["artifact-ids"], run(needs));
		expect(id({ evidence: routed("public"), "evidence-security": secured("skipped") })).toBe("11");
		expect(id({ evidence: routed("security"), "evidence-security": secured("success") })).toBe(
			"22",
		);
	});

	it("reads the security repository only where the evidence job says so, the tag's message read for it", () => {
		const security = workflow.jobs["evidence-security"];
		expect(conditionOf(security?.if, run({ evidence: routed("security") }))).toBe(true);
		expect(conditionOf(security?.if, run({ evidence: routed("public") }))).toBe(false);
		expect(conditionOf(security?.if, run({ evidence: routed("security", "failure") }))).toBe(false);
		const judge = (job: string) =>
			workflow.jobs[job]?.steps?.find((s) => s.run?.includes("judge.ts"));
		expect(judge("evidence")?.env).toBeUndefined();
		expect(judge("evidence-security")?.env).toBeUndefined();
		for (const job of ["evidence", "evidence-security"]) {
			const checkout = workflow.jobs[job]?.steps?.find((s) =>
				s.uses?.startsWith("actions/checkout@"),
			);
			expect(checkout?.with, job).toMatchObject({ "fetch-depth": 0 });
		}
		const kept = evidence?.steps?.find((s) => s.id === "kept");
		expect(kept?.if).toBe("steps.judge.outputs.route == 'public'");
	});

	it("wires each job's outputs to the steps that make them", () => {
		const outputs = (job: string) =>
			(workflow.jobs[job] as { outputs?: Record<string, string> } | undefined)?.outputs;
		const step = (job: string, id: string) => workflow.jobs[job]?.steps?.find((s) => s.id === id);
		expect(outputs("evidence")).toEqual({
			evidence: "${{ steps.kept.outputs.artifact-id }}",
			route: "${{ steps.judge.outputs.route }}",
		});
		expect(step("evidence", "judge")?.run).toContain("release-evidence/judge.ts");
		expect(step("evidence", "kept")?.uses).toMatch(/^actions\/upload-artifact@/);
		expect(outputs("evidence-security")).toEqual({
			evidence: "${{ steps.kept.outputs.artifact-id }}",
		});
		expect(step("evidence-security", "kept")?.uses).toMatch(/^actions\/upload-artifact@/);
		expect(step("evidence-security", "app")?.uses).toMatch(/^actions\/create-github-app-token@/);
	});

	it("builds the API site after a final release's publish alone", () => {
		const site = (publish: string, over: Partial<RunContext> = {}) =>
			conditionOf(workflow.jobs["api-docs"]?.if, run({ publish: { result: publish } }, over));
		expect(site("success")).toBe(true);
		expect(site("success", { ref_name: "v1.0.1-rc.1" })).toBe(false);
		expect(site("skipped")).toBe(false);
		expect(site("failure")).toBe(false);
		expect(site("success", { cancelled: true })).toBe(false);
	});
});

describe("the security repository's evidence job", () => {
	const job = workflow.jobs["evidence-security"];
	const steps = job?.steps ?? [];

	it("runs in the approved environment, reading the one repository written here, with no permission of its own", () => {
		expect(job?.environment).toBe("security-evidence");
		expect(job?.permissions).toEqual({ contents: "read" });
		expect(job?.env).toEqual({ EVIDENCE_REPOSITORY: "o3co/auth.provider-security" });
	});

	it("asks the App for a token that reads that repository's runs alone", () => {
		const app = steps.find((s) => s.uses?.startsWith("actions/create-github-app-token@"));
		expect(app?.uses).toMatch(/@[0-9a-f]{40}$/);
		const permissions = Object.keys(app?.with ?? {}).filter((k) => k.startsWith("permission-"));
		expect(permissions).toEqual(["permission-actions"]);
		expect(app?.with).toMatchObject({
			owner: "o3co",
			repositories: "auth.provider-security",
			"permission-actions": "read",
		});
		expect(app?.with).not.toHaveProperty("skip-token-revoke");
	});

	it("uses the token to fetch alone, revokes it as fetching ends, and installs and judges only once it is refused", () => {
		const holding = steps.flatMap((s, i) =>
			JSON.stringify(s.env ?? {}).includes("steps.app.outputs.token") ? [i] : [],
		);
		const fetchAt = steps.findIndex((s) => s.run?.includes("release-evidence/fetch.ts"));
		const refusedAt = steps.findIndex((s) => s.name === "The token is revoked");
		expect(holding).toEqual([fetchAt, refusedAt]);
		expect(steps[fetchAt]?.run).toContain("trap 'gh api --method DELETE /installation/token");
		expect(steps[refusedAt]?.run).toContain('"$code" != 401');
		const install = steps.findIndex((s) => s.run?.includes("pnpm install"));
		const judge = steps.findIndex((s) => s.run?.includes("release-evidence/judge.ts"));
		expect(install).toBeGreaterThan(refusedAt);
		expect(judge).toBeGreaterThan(install);
		expect(steps[install]?.run).toContain("--ignore-scripts");
	});
});

describe("the security repository's token, as its steps run", () => {
	const steps = workflow.jobs["evidence-security"]?.steps ?? [];
	const fetching = steps.find((s) => s.run?.includes("release-evidence/fetch.ts"));
	const refused = steps.find((s) => s.name === "The token is revoked");
	/** Runs a step's script under bash, with `node`, `gh` and `curl` stood in by the scripts given. */
	const ran = (script: string | undefined, tools: Record<string, string>) => {
		const bin = mkdtempSync(join(tmpdir(), "release-evidence-steps-"));
		const log = join(bin, "log");
		writeFileSync(log, "");
		for (const [tool, body] of Object.entries(tools)) {
			writeFileSync(join(bin, tool), `#!/bin/sh\necho "${tool} $*" >> ${log}\n${body}\n`);
			chmodSync(join(bin, tool), 0o755);
		}
		const done = spawnSync("bash", ["-c", script ?? "exit 99"], {
			encoding: "utf8",
			env: { PATH: `${bin}:${process.env.PATH ?? ""}`, GH_TOKEN: "t", RUNNER_TEMP: bin },
		});
		return { status: done.status, log: readFileSync(log, "utf8") };
	};

	it("revokes the token as fetching ends, whether fetching passed or failed", () => {
		for (const [node, status] of [
			["exit 0", 0],
			["exit 1", 1],
		] as const) {
			const done = ran(fetching?.run, { node, gh: "exit 0" });
			expect(done.status).toBe(status);
			expect(done.log).toContain("gh api --method DELETE /installation/token");
		}
	});

	it("goes on only where the token is refused", () => {
		expect(ran(refused?.run, { curl: "printf 401" }).status).toBe(0);
		for (const code of ["200", "403", "000"]) {
			expect(ran(refused?.run, { curl: `printf ${code}` }).status, code).not.toBe(0);
		}
	});
});

describe("the tag the release reads", () => {
	it("is fetched again as pushed, after the checkout and before anything fetches or judges", () => {
		for (const job of ["evidence", "evidence-security"]) {
			const steps = workflow.jobs[job]?.steps ?? [];
			const at = (found: (s: (typeof steps)[number]) => boolean) => steps.findIndex(found);
			const checkout = at((s) => s.uses?.startsWith("actions/checkout@") === true);
			const tag = at((s) => s.name === "The tag as pushed");
			const fetching = at((s) => s.run?.includes("release-evidence/fetch.ts") === true);
			const judging = at((s) => s.run?.includes("release-evidence/judge.ts") === true);
			expect([checkout < tag, tag < fetching, tag < judging], job).toEqual([true, true, true]);
		}
	});

	it("comes back annotated, its declaration kept, where the checkout wrote it lightweight", () => {
		const step = workflow.jobs.evidence?.steps?.find((s) => s.name === "The tag as pushed");
		const pushed = mkdtempSync(join(tmpdir(), "release-evidence-pushed-"));
		const git = (cwd: string, ...args: string[]) =>
			spawnSync(
				"git",
				["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", ...args],
				{
					cwd,
					encoding: "utf8",
				},
			).stdout.trim();
		git(pushed, "init", "-q", "-b", "main");
		git(pushed, "commit", "-q", "--allow-empty", "-m", "a");
		git(pushed, "tag", "-a", "v1.0.1", "-m", "v1.0.1", "-m", "Release-Evidence: security");
		const checkout = mkdtempSync(join(tmpdir(), "release-evidence-checkout-"));
		spawnSync("git", ["clone", "-q", "--no-tags", pushed, checkout]);
		// As the checkout leaves it: the tag written again as a lightweight tag at the commit.
		git(checkout, "tag", "-f", "v1.0.1", "HEAD");
		expect(git(checkout, "cat-file", "-t", "refs/tags/v1.0.1")).toBe("commit");
		const done = spawnSync("bash", ["-c", step?.run ?? "exit 99"], {
			cwd: checkout,
			encoding: "utf8",
			env: {
				PATH: process.env.PATH ?? "",
				HOME: process.env.HOME ?? "",
				GITHUB_REF_NAME: "v1.0.1",
			},
		});
		expect(done.status).toBe(0);
		expect(git(checkout, "cat-file", "-t", "refs/tags/v1.0.1")).toBe("tag");
		expect(git(checkout, "cat-file", "tag", "refs/tags/v1.0.1")).toContain(
			"Release-Evidence: security",
		);
	});
});
