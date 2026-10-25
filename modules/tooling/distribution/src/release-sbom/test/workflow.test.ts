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
		(s) =>
			uses("actions/download-artifact")(s) &&
			s.with?.["artifact-ids"] === "${{ needs.pack.outputs.tarballs }}",
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
		(s) =>
			uses("actions/download-artifact")(s) &&
			s.with?.["artifact-ids"] === "${{ needs.pack.outputs.tarballs }}",
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

/** The API site's workflow, which the release calls once it has published. */
const site = parse(
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
			"api-docs.yml",
		),
		"utf8",
	),
) as { readonly jobs: Record<string, Job> };
const downloads = (job: Job | undefined) =>
	(job?.steps ?? []).filter(uses("actions/download-artifact"));

it("takes each artifact by the id the job that made it gave, never by a name another job could make again", () => {
	const outputs = (name: string) =>
		(jobs[name] as Job & { outputs?: Record<string, string> }).outputs ?? {};
	expect(outputs("pack").tarballs).toMatch(/steps\.\w+\.outputs\.artifact-id/);
	expect(outputs("pack").run).toMatch(/steps\.\w+\.outputs\.artifact-id/);
	expect(outputs("sbom").lists).toMatch(/steps\.\w+\.outputs\.artifact-id/);
	expect(outputs("evidence").evidence).toMatch(/steps\.\w+\.outputs\.artifact-id/);
	for (const [job, by] of [
		["sbom", ["needs.pack.outputs.tarballs"]],
		[
			"publish",
			[
				"needs.pack.outputs.tarballs",
				"needs.sbom.outputs.lists",
				"needs.evidence.outputs.evidence",
				"needs.pack.outputs.run",
			],
		],
	] as const) {
		const taken = downloads(jobs[job]);
		expect(taken.map((s) => s.with?.name).filter(Boolean), job).toEqual([]);
		expect(taken.map((s) => String(s.with?.["artifact-ids"])).sort(), job).toEqual(
			by.map((o) => `\${{ ${o} }}`).sort(),
		);
	}
});

it("takes from the registry what npm holds, packs the rest, and checks the very tarballs it keeps", () => {
	const pack = jobs.pack;
	// No artifact is restored: a run again takes what npm holds from the registry, of its integrity.
	expect(downloads(pack)).toEqual([]);
	const packed = only(
		pack,
		runs('.github/scripts/pack-published.sh "$RUNNER_TEMP/tarballs" --from-registry'),
	);
	const licensed = only(pack, runs("check-tarball-license.sh"));
	const checked = only(pack, runs('pnpm release:check "$RUNNER_TEMP/tarballs"'));
	const kept = only(
		pack,
		(s) => uses("actions/upload-artifact")(s) && s.with?.name === "release-tarballs",
	);
	const recorded = only(pack, runs("fetched.json"));
	expect([packed, licensed, checked, kept]).toEqual(
		[packed, licensed, checked, kept].sort((a, b) => a - b),
	);
	const steps = pack?.steps ?? [];
	expect(steps[kept]?.with?.overwrite).toBe(true);
	expect(String(steps[kept]?.with?.path)).toContain("publish-order.json");
	expect(steps[recorded]?.run).toContain("release-run");
	for (const at of [packed, licensed, checked])
		expect((steps[at] as Step & { if?: unknown }).if).toBeUndefined();
});

it("publishes in the order the pack wrote, the index's bundle after every bundle it seals over", () => {
	const publish = jobs.publish;
	const npm = only(publish, runs("npm publish"));
	expect((publish?.steps ?? [])[npm]?.run).toContain('"$RUNNER_TEMP/tarballs/publish-order.json"');
});

it("skips no job of the release, nor a step that holds it, but by success", () => {
	const plain = (cond: unknown) =>
		cond === undefined || cond === "success()" || cond === "${{ success() }}";
	for (const name of ["evidence", "pack", "sbom", "publish"]) {
		expect((jobs[name] as Job & { if?: unknown }).if, name).toSatisfy(plain);
	}
	const held = [
		[jobs.pack, runs("pnpm release:check")],
		[jobs.pack, runs("check-tarball-license.sh")],
		[jobs.sbom, runs("pnpm release:sbom")],
		[jobs.publish, runs("pnpm release:listed")],
		[jobs.publish, runs("pnpm release:published")],
		[jobs.publish, uses("softprops/action-gh-release")],
		[jobs.publish, runs("npm publish")],
	] as const;
	for (const [job, found] of held) {
		for (const s of (job?.steps ?? []).filter(found))
			expect((s as Step & { if?: unknown }).if, s.name ?? s.run).toSatisfy(plain);
	}
});

it("pins every action from outside GitHub by its commit, in the release and the API site alike", () => {
	const all = [...Object.values(jobs), ...Object.values(site.jobs)].flatMap(
		(job) => job.steps ?? [],
	);
	const outside = all.flatMap((s) =>
		s.uses && !s.uses.startsWith("actions/") && !s.uses.startsWith("./") ? [s.uses] : [],
	);
	expect(outside.length).toBeGreaterThan(0);
	for (const action of outside) expect(action).toMatch(/@[0-9a-f]{40}$/);
});

it("keeps the API site's credentials out of its checkouts and its install, the token in the push alone", () => {
	const steps = site.jobs.site?.steps ?? [];
	for (const checkout of steps.filter(uses("actions/checkout")))
		expect(checkout.with?.["persist-credentials"]).toBe(false);
	for (const install of steps.filter(runs("pnpm install")))
		expect(install.run).toContain("--ignore-scripts");
	const tokened = steps.filter((s) =>
		JSON.stringify((s as Step & { env?: unknown }).env ?? {}).includes("github.token"),
	);
	expect(tokened.map((s) => s.name)).toEqual(["Publish the pages"]);
});
