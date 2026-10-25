import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

/** The release workflow's publish job, read as GitHub reads it. */
const publish = (
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
	) as {
		readonly jobs: Record<
			string,
			{
				readonly steps: readonly {
					readonly name?: string;
					readonly run?: string;
					readonly uses?: string;
					readonly with?: Record<string, unknown>;
				}[];
			}
		>;
	}
).jobs.publish;

it("makes the lists from the tarballs it checked, before the draft release, and attaches them to it", () => {
	const steps = publish?.steps ?? [];
	const at = (found: (s: (typeof steps)[number]) => boolean) => steps.findIndex(found);
	const lists = at((s) => s.run?.includes('pnpm release:sbom "$RUNNER_TEMP/tarballs"') ?? false);
	const checked = at((s) => s.run?.includes("pnpm release:published") ?? false);
	const draft = at((s) => s.uses?.startsWith("softprops/action-gh-release@") ?? false);
	expect(lists).toBeGreaterThan(checked);
	expect(draft).toBeGreaterThan(lists);
	expect(String(steps[draft]?.with?.files)).toContain("-sbom.tar.gz");
	expect(steps[draft]?.with?.fail_on_unmatched_files).toBe(true);
});
