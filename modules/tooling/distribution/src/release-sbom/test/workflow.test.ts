import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

interface Step {
	readonly name?: string;
	readonly run?: string;
	readonly uses?: string;
	readonly with?: Record<string, unknown>;
	readonly "continue-on-error"?: unknown;
}
interface Job {
	readonly needs?: string | readonly string[];
	readonly permissions?: Record<string, string>;
	readonly steps?: readonly Step[];
}
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
) as { readonly permissions?: Record<string, string>; readonly jobs: Record<string, Job> };
const { jobs } = workflow;
const needsOf = (job: Job | undefined) =>
	typeof job?.needs === "string" ? [job.needs] : (job?.needs ?? []);
/** The index of the one step that matches, failing where none or several do. */
const only = (job: Job | undefined, found: (s: Step) => boolean) => {
	const at = (job?.steps ?? []).flatMap((s, i) => (found(s) ? [i] : []));
	expect(at, "one step").toHaveLength(1);
	return at[0] as number;
};
const runs = (text: string) => (s: Step) => s.run?.includes(text) ?? false;
const uses = (action: string) => (s: Step) => s.uses?.startsWith(`${action}@`) ?? false;
/** A step whose failure would not stop its job. */
const forgiving = (s: Step) =>
	s["continue-on-error"] !== undefined || /\|\|\s*true/.test(s.run ?? "");

it("gives the publish job alone what publishing takes, every job running packed code nothing past reading", () => {
	expect(workflow.permissions).toEqual({ contents: "read" });
	expect(jobs.publish?.permissions).toEqual({ contents: "write", "id-token": "write" });
	expect(jobs.pack?.permissions).toEqual({ contents: "read" });
	expect(jobs.sbom?.permissions).toEqual({ contents: "read" });
	const tokens = Object.entries(jobs).filter(
		([, job]) => job.permissions?.["id-token"] !== undefined,
	);
	expect(tokens.map(([name]) => name)).toEqual(["publish"]);
});

it("runs nothing the release packed where it publishes", () => {
	const steps = jobs.publish?.steps ?? [];
	for (const text of [
		"release:check",
		"release:sbom",
		"pnpm check",
		"pnpm bundles",
		"create-auth-provider ",
	]) {
		expect(
			steps.filter(runs(text)).map((s) => s.name ?? s.run),
			text,
		).toEqual([]);
	}
	for (const install of steps.filter(runs("pnpm install")))
		expect(install.run).toContain("--ignore-scripts");
});

it("makes the lists in a job of their own, from the tarballs the pack job kept, any failure stopping it", () => {
	const sbom = jobs.sbom;
	expect(needsOf(sbom)).toContain("pack");
	const taken = only(
		sbom,
		(s) => uses("actions/download-artifact")(s) && s.with?.name === "release-tarballs",
	);
	const made = only(sbom, runs('pnpm release:sbom "$RUNNER_TEMP/tarballs"'));
	const kept = only(
		sbom,
		(s) => uses("actions/upload-artifact")(s) && s.with?.name === "release-sbom",
	);
	expect(taken).toBeLessThan(made);
	expect(made).toBeLessThan(kept);
	expect((sbom?.steps ?? []).filter(forgiving)).toEqual([]);
});

it("publishes only the tarballs the lists were made of, after every check, each check's failure stopping it", () => {
	const publish = jobs.publish;
	expect(needsOf(publish)).toEqual(expect.arrayContaining(["evidence", "pack", "sbom"]));
	const taken = only(
		publish,
		(s) => uses("actions/download-artifact")(s) && s.with?.name === "release-tarballs",
	);
	const listed = only(publish, runs('pnpm release:listed "$RUNNER_TEMP/tarballs"'));
	const published = only(publish, runs('pnpm release:published "$RUNNER_TEMP/tarballs"'));
	const draft = only(publish, uses("softprops/action-gh-release"));
	const npm = only(publish, runs("npm publish"));
	expect([taken, listed, published, draft, npm]).toEqual(
		[...[taken, listed, published, draft, npm]].sort((a, b) => a - b),
	);
	const steps = publish?.steps ?? [];
	for (const at of [listed, published]) expect(forgiving(steps[at] as Step)).toBe(false);
	expect(String(steps[draft]?.with?.files)).toContain("-sbom.tar.gz");
	expect(String(steps[draft]?.with?.files)).toContain("-evidence.tar.gz");
	expect(steps[draft]?.with?.fail_on_unmatched_files).toBe(true);
});
