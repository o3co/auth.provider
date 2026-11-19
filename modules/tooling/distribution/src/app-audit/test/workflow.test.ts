import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";

interface Step {
	readonly run?: string;
	readonly uses?: string;
}
const ci = parse(
	readFileSync(
		join(import.meta.dirname, "..", "..", "..", "..", "..", "..", ".github", "workflows", "ci.yml"),
		"utf8",
	),
) as { readonly jobs: Record<string, { readonly steps?: readonly Step[] }> };
const steps = ci.jobs.audit?.steps ?? [];

/** The actions the job may use, in order: the checkout and the toolchain, nothing that audits. */
const actions = ["actions/checkout@", "pnpm/action-setup@", "actions/setup-node@"];
/** The commands the job may run, in order, each as its lines: install, pack, audit the app. */
const commands = [
	["pnpm install --frozen-lockfile"],
	[
		"set -euo pipefail",
		"pnpm bundles",
		'.github/scripts/pack-published.sh "$RUNNER_TEMP/tarballs"',
	],
	['pnpm app:audit "$RUNNER_TEMP/tarballs"'],
];

/** Whether the job's steps are exactly those: no other audit, filter or choice of packages. */
const held = (given: readonly Step[]) => {
	const uses = given.filter((s) => s.uses !== undefined).map((s) => s.uses ?? "");
	const runs = given
		.filter((s) => s.run !== undefined)
		.map((s) =>
			(s.run ?? "")
				.split("\n")
				.map((line) => line.trim())
				.filter((line) => line !== ""),
		);
	return (
		given.every((s) => (s.uses === undefined) !== (s.run === undefined)) &&
		uses.length === actions.length &&
		uses.every((u, i) => u.startsWith(actions[i] ?? "\0")) &&
		JSON.stringify(runs) === JSON.stringify(commands)
	);
};

it("installs, packs the release and audits its app's install, and runs nothing else", () => {
	expect(held(steps)).toBe(true);
});

const withRun = (run: string): readonly Step[] => [...steps, { run }];
it.each([
	[
		"without the install and the bundles",
		steps.filter((s) => !/pnpm (install|bundles)/.test(s.run ?? "")),
	],
	["with an audit of its own", withRun("pnpm audit --prod --audit-level=low")],
	[
		"with a filtered audit",
		withRun("pnpm --filter @mod/conformance audit --prod --audit-level=low"),
	],
	["with packages dropped from the lockfile", withRun("pnpm remove vitest picomatch")],
	["with the app audited before the pack", [...steps].reverse()],
	["with an action of another's", [...steps, { uses: "someone/audit-action@v1" }]],
])("refuses the job %s", (_, mutated) => {
	expect(held(mutated)).toBe(false);
});
