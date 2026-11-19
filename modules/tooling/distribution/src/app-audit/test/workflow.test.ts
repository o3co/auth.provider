import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

interface Step {
	readonly run?: string;
}
const ci = parse(
	readFileSync(
		join(import.meta.dirname, "..", "..", "..", "..", "..", "..", ".github", "workflows", "ci.yml"),
		"utf8",
	),
) as { readonly jobs: Record<string, { readonly steps?: readonly Step[] }> };
const runs = (ci.jobs.audit?.steps ?? []).map((s) => s.run ?? "");

it("packs the release and audits its app's install, and nothing else", () => {
	const pack = runs.findIndex((r) => r.includes(".github/scripts/pack-published.sh"));
	const audit = runs.findIndex((r) => /^pnpm app:audit "\$RUNNER_TEMP\/tarballs"$/.test(r.trim()));
	expect(pack).toBeGreaterThanOrEqual(0);
	expect(audit).toBeGreaterThan(pack);
});

it("runs no audit of its own, so no list of what to audit or leave out lives in the job", () => {
	expect(runs.filter((r) => /\bpnpm audit\b|\bnpm audit\b/.test(r))).toEqual([]);
});
