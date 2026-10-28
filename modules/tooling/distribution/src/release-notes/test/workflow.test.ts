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

/** The release workflow's publish job, read as GitHub reads it. */
const steps: readonly Step[] =
	(
		parse(
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
		) as { readonly jobs: Record<string, { readonly steps?: readonly Step[] }> }
	).jobs.publish?.steps ?? [];

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
