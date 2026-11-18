import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";

it("declares the unclaimed-factors script, naming the subjects resetCandidates counts unclaimed factors for", () => {
	const manifest = JSON.parse(
		readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"),
	);
	expect(manifest.appEntries).toEqual([
		{
			script: "unclaimed-factors",
			shape: "name-subjects",
			contract: "resetCandidates",
			member: "unclaimed",
		},
	]);
});
