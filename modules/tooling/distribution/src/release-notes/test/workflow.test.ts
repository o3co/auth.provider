import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

type Step = {
	readonly name?: string;
	readonly id?: string;
	readonly uses?: string;
	readonly run?: string;
	readonly "continue-on-error"?: unknown;
	readonly with?: Record<string, unknown>;
};

type Job = { readonly if?: string; readonly steps?: readonly Step[] };

/** A workflow's jobs, read as GitHub reads it. */
const jobsOf = (file: string) =>
	(
		parse(
			readFileSync(
				join(import.meta.dirname, "..", "..", "..", "..", "..", "..", ".github", "workflows", file),
				"utf8",
			),
		) as { readonly jobs: Record<string, Job> }
	).jobs;
const steps: readonly Step[] = jobsOf("release.yml").publish?.steps ?? [];

it("drafts the release with the notes of the version's changelog section, never notes GitHub generates", () => {
	const written = steps.findIndex((s) => s.run?.includes("pnpm release:notes") === true);
	const draft = steps.findIndex((s) => s.uses?.startsWith("softprops/action-gh-release@") === true);
	expect(written).toBeGreaterThan(-1);
	expect(written).toBeLessThan(draft);
	expect(steps[written]?.["continue-on-error"]).toBeUndefined();
	expect(steps[written]?.run).toContain('"$RUNNER_TEMP/release-notes.md"');
	expect(steps[draft]?.with?.body_path).toBe("${{ runner.temp }}/release-notes.md");
	expect(steps[draft]?.with?.generate_release_notes).toBeUndefined();
});

it("writes the version's notes on the release branch's CI too, before the release check, so a missing section stops before the tag", () => {
	const job = jobsOf("ci.yml")["release-check"];
	expect(job?.if).toContain("refs/heads/release/");
	const ran = job?.steps ?? [];
	const written = ran.findIndex((s) => s.run?.includes("pnpm release:notes") === true);
	const checked = ran.findIndex((s) => s.run === "pnpm release:check");
	expect(written).toBeGreaterThan(-1);
	expect(written).toBeLessThan(checked);
	expect(ran[written]?.["continue-on-error"]).toBeUndefined();
	expect(ran[written]?.run).toContain("package.json");
});
