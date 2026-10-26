import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

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
			readonly permissions?: Record<string, string>;
			readonly steps?: readonly {
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
