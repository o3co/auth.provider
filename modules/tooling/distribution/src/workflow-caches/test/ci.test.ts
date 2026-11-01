import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

/** CI's workflow, read as GitHub reads it: the runs a release's evidence comes from. */
const text = readFileSync(
	join(import.meta.dirname, "..", "..", "..", "..", "..", "..", ".github", "workflows", "ci.yml"),
	"utf8",
);
const workflow = parse(text) as {
	readonly jobs: Record<
		string,
		{
			readonly needs?: string | readonly string[];
			readonly outputs?: Record<string, string>;
			readonly steps?: readonly {
				readonly id?: string;
				readonly uses?: string;
				readonly with?: Record<string, unknown>;
			}[];
		}
	>;
};
const needsOf = (job: string) => {
	const needs = workflow.jobs[job]?.needs;
	return typeof needs === "string" ? [needs] : (needs ?? []);
};

it("builds the legacy system once and hands it to each area as this run's own artifact, by its id", () => {
	const build = workflow.jobs["legacy-build"];
	const kept = build?.steps?.find((s) => s.uses?.startsWith("actions/upload-artifact@"));
	expect(kept?.with).toMatchObject({ name: "legacy-build", overwrite: true });
	expect(build?.outputs?.legacy).toBe(`\${{ steps.${kept?.id}.outputs.artifact-id }}`);

	expect(needsOf("conformance-area")).toContain("legacy-build");
	const take = workflow.jobs["conformance-area"]?.steps?.find((s) =>
		s.uses?.startsWith("actions/download-artifact@"),
	);
	expect(take?.with?.["artifact-ids"]).toBe("${{ needs.legacy-build.outputs.legacy }}");
	expect(take?.with).not.toHaveProperty("run-id");
	expect(take?.with).not.toHaveProperty("github-token");
});

it("keeps the legacy build as long as an area's evidence, so a re-run of a failed area still finds it", () => {
	const kept = (job: string, name: (n: unknown) => boolean) =>
		workflow.jobs[job]?.steps?.find(
			(s) => s.uses?.startsWith("actions/upload-artifact@") && name(s.with?.name),
		)?.with?.["retention-days"];
	const legacy = kept("legacy-build", (n) => n === "legacy-build");
	expect(legacy).toBeGreaterThanOrEqual(
		kept("conformance-area", (n) => String(n).startsWith("evidence-area-")) as number,
	);
});

it("fails conformance where the legacy build did not pass", () => {
	expect(needsOf("conformance")).toContain("legacy-build");
});

it("lets a re-run of compliance write over the table an earlier attempt kept", () => {
	const upload = workflow.jobs.compliance?.steps?.find((s) =>
		s.uses?.startsWith("actions/upload-artifact@"),
	);
	expect(upload?.with).toMatchObject({ name: "compliance", overwrite: true });
});

it("never chooses the legacy commit by a ref or by hand: conformance-legacy's tree names it", () => {
	expect(text).not.toMatch(/LEGACY_(BRANCH|COMMIT)/);
});
