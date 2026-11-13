import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { parse } from "yaml";

interface Step {
	readonly run?: string;
	readonly uses?: string;
	readonly if?: string;
	readonly env?: Record<string, unknown>;
	readonly with?: Record<string, unknown>;
	readonly "working-directory"?: string;
}
interface Job {
	readonly if?: string;
	readonly needs?: unknown;
	readonly env?: Record<string, unknown>;
	readonly outputs?: Record<string, unknown>;
	readonly strategy?: { readonly "fail-fast"?: unknown; readonly matrix?: unknown };
	readonly permissions?: unknown;
	readonly "timeout-minutes"?: unknown;
	readonly "continue-on-error"?: unknown;
	readonly steps?: readonly Step[];
}
const workflows = join(
	import.meta.dirname,
	"..",
	"..",
	"..",
	"..",
	"..",
	"..",
	".github",
	"workflows",
);
const text = readFileSync(join(workflows, "image-scan.yml"), "utf8");
/** The scan's workflow, read as GitHub reads it. */
const workflow = parse(text) as {
	readonly on: Record<string, unknown>;
	readonly permissions?: unknown;
	readonly jobs: Record<string, Job>;
};
const resolve = (workflow.jobs.resolve ?? {}) as Job;
const scan = (workflow.jobs["image-scan"] ?? {}) as Job;
const steps = scan.steps ?? [];
const token = "${{ github.token }}";

it("runs on its daily schedule and a manual run alone, the manual run taking no input", () => {
	expect(Object.keys(workflow.on).toSorted()).toEqual(["schedule", "workflow_dispatch"]);
	expect(workflow.on.workflow_dispatch ?? null).toBeNull();
	expect(Object.keys(workflow.jobs)).toEqual(["resolve", "image-scan"]);
	expect(workflow.permissions).toEqual({ contents: "read" });
});

it("resolves its targets in a job that runs no code of the repository, the only one given the run's token", () => {
	const only = resolve.steps ?? [];
	expect(only).toHaveLength(1);
	expect(only[0]?.uses).toBeUndefined();
	expect(only[0]?.env).toEqual({ GH_TOKEN: token });
	expect(resolve.permissions).toEqual({ contents: "read" });
	expect(typeof resolve["timeout-minutes"]).toBe("number");
	expect(text.split("github.token")).toHaveLength(2);
	expect(text).not.toMatch(/secrets\.|GITHUB_TOKEN/);
});

it("lists develop, the latest release, and each older minor still supported as X.Y", () => {
	const targets = String(resolve.env?.TARGETS).trim().split(/\s+/);
	expect(targets.slice(0, 2)).toEqual(["develop", "latest"]);
	for (const target of targets.slice(2)) expect(target).toMatch(/^[0-9]+\.[0-9]+$/);
});

it("scans each target in a job of its own, reading alone, within a time, one failing stopping no other", () => {
	expect(scan.needs).toBe("resolve");
	expect(scan.strategy?.["fail-fast"]).toBe(false);
	expect(scan.strategy?.matrix).toEqual({
		include: "${{ fromJSON(needs.resolve.outputs.targets) }}",
	});
	expect(resolve.outputs?.targets).toBe("${{ steps.targets.outputs.targets }}");
	expect(scan.permissions).toEqual({ contents: "read" });
	expect(typeof scan["timeout-minutes"]).toBe("number");
	expect(scan["continue-on-error"]).toBeUndefined();
});

it("packs the target from its own checkout, and scans it with the scanner of the commit the workflow runs on", () => {
	const checkout = steps.filter((s) => s.uses?.startsWith("actions/checkout@"));
	expect(checkout.map((s) => s.with)).toEqual([
		{ path: "scanner", "persist-credentials": false },
		{ ref: "${{ matrix.ref }}", path: "target", "persist-credentials": false },
	]);
	const at = (command: string) => steps.findIndex((s) => s.run?.includes(command));
	const pack = steps[at("pnpm bundles")];
	expect(pack?.["working-directory"]).toBe("target");
	const packing = pack?.run ?? "";
	expect(packing.indexOf("pnpm install --frozen-lockfile")).toBeGreaterThanOrEqual(0);
	expect(packing.indexOf("pnpm bundles")).toBeGreaterThan(
		packing.indexOf("pnpm install --frozen-lockfile"),
	);
	expect(
		packing.indexOf('.github/scripts/pack-published.sh "$RUNNER_TEMP/tarballs"'),
	).toBeGreaterThan(packing.indexOf("pnpm bundles"));
	const scanning = steps[at("pnpm image:scan")];
	expect(scanning?.["working-directory"]).toBe("scanner");
	expect(scanning?.run).toContain("pnpm install --frozen-lockfile");
	expect(scanning?.run).toContain(
		'pnpm image:scan "$RUNNER_TEMP/tarballs" "$RUNNER_TEMP/image-scan"',
	);
	expect(at("pnpm image:scan")).toBeGreaterThan(at("pnpm bundles"));
	const pnpm = steps.find((s) => s.uses?.startsWith("pnpm/action-setup@"));
	expect(pnpm?.with).toEqual({ package_json_file: "scanner/package.json" });
});

it("restores and saves no cache", () => {
	expect(steps.filter((s) => s.uses?.startsWith("actions/cache"))).toEqual([]);
	for (const step of steps.filter((s) =>
		/^(actions\/setup-node|pnpm\/action-setup)@/.test(s.uses ?? ""),
	)) {
		expect(Object.keys(step.with ?? {})).not.toContain("cache");
		expect(Object.keys(step.with ?? {})).not.toContain("run_install");
	}
});

it("keeps what it found for each target however the scan ended", () => {
	const at = (command: string) => steps.findIndex((s) => s.run?.includes(command));
	const summary = steps.findIndex((s) => s.run?.includes("$GITHUB_STEP_SUMMARY"));
	expect(summary).toBeGreaterThan(at("pnpm image:scan"));
	expect(steps[summary]?.if).toBe("always()");
	expect(steps[summary]?.env).toEqual({ TARGET: "${{ matrix.target }}", REF: "${{ matrix.ref }}" });
	const kept = steps.filter((s) => s.uses?.startsWith("actions/upload-artifact@"));
	expect(kept).toHaveLength(1);
	expect(kept[0]?.if).toBe("always()");
	expect(kept[0]?.with?.name).toBe("image-scan-trivy-${{ matrix.target }}");
	expect(String(kept[0]?.with?.path)).toMatch(/image\.trivy\.json$/);
	expect(kept[0]?.with?.["retention-days"]).toBe(7);
});

describe("resolving the targets", () => {
	// The resolve step's script, run by bash with a `gh` of its own first on the path, which answers
	// from the tags the test gives as GitHub would, its `--jq` applied by jq.
	const scratch = mkdtempSync(join(tmpdir(), "image-scan-targets-"));
	afterAll(() => rmSync(scratch, { recursive: true, force: true }));
	const bin = join(scratch, "bin");
	mkdirSync(bin);
	writeFileSync(
		join(bin, "gh"),
		`#!/usr/bin/env bash
set -euo pipefail
jq_expr=""; path=""
for ((i = 1; i <= $#; i++)); do
	case "\${!i}" in
		--jq) j=$((i + 1)); jq_expr="\${!j}" ;;
		repos/*) path="\${!i}" ;;
	esac
done
case "$1" in
	release) jq -cn --arg t "$FAKE_LATEST" '{tagName: $t}' | jq -r "$jq_expr" ;;
	api)
		prefix="refs/\${path#*/git/matching-refs/}"
		printf '%s\\n' $FAKE_TAGS | jq -R --arg p "$prefix" '"refs/tags/" + .' \\
			| jq -s --arg p "$prefix" 'map(select(startswith($p)) | {ref: .})' | jq -r "$jq_expr" ;;
	*) exit 9 ;;
esac
`,
	);
	chmodSync(join(bin, "gh"), 0o755);
	const script = join(scratch, "resolve.sh");
	writeFileSync(script, (resolve.steps ?? [])[0]?.run ?? "");

	const resolved = (targets: string, tags: string, latest = "v0.19.2") => {
		const output = join(scratch, `output-${Math.random().toString(36).slice(2)}`);
		writeFileSync(output, "");
		const ran = spawnSync("bash", ["-e", script], {
			encoding: "utf8",
			env: {
				...process.env,
				PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
				TARGETS: targets,
				GITHUB_OUTPUT: output,
				GITHUB_REPOSITORY: "o3co/auth.provider",
				FAKE_LATEST: latest,
				FAKE_TAGS: tags,
			},
		});
		const line = readFileSync(output, "utf8")
			.split("\n")
			.find((l) => l.startsWith("targets="));
		return {
			status: ran.status,
			told: ran.stdout + ran.stderr,
			targets: line ? JSON.parse(line.slice("targets=".length)) : undefined,
		};
	};
	const tags = "v0.18.4 v0.19.0-rc.1 v0.19.0 v0.19.2 v0.19.10 v0.19.11-rc.1 v0.190.1";

	it("names develop as itself and the latest release by its tag", () => {
		expect(resolved("develop latest", tags)).toEqual({
			status: 0,
			told: "",
			targets: [
				{ target: "develop", ref: "develop" },
				{ target: "latest", ref: "v0.19.2" },
			],
		});
	});

	it("takes a minor's highest release tag, by version, leaving out release candidates", () => {
		expect(resolved("0.19 0.18", tags).targets).toEqual([
			{ target: "0.19", ref: "v0.19.10" },
			{ target: "0.18", ref: "v0.18.4" },
		]);
	});

	it("fails a minor with no release tag", () => {
		const { status, told, targets } = resolved("develop 0.17", tags);
		expect(status).not.toBe(0);
		expect(told).toContain("0.17 has no release tag vX.Y.Z: ''");
		expect(targets).toBeUndefined();
	});

	it("fails a target that is neither develop, latest nor a minor", () => {
		for (const target of ["main", "0.19.2", "v0.19", "0.19.x"]) {
			const { status, told } = resolved(target, tags);
			expect(status).not.toBe(0);
			expect(told).toContain(`a target is develop, latest or a minor X.Y: '${target}'`);
		}
	});

	it("fails a latest release whose tag is not vX.Y.Z", () => {
		const { status, told } = resolved("latest", tags, "release-0.19.2");
		expect(status).not.toBe(0);
		expect(told).toContain("latest has no release tag vX.Y.Z: 'release-0.19.2'");
	});

	it("fails an empty list", () => {
		const { status, told } = resolved(" ", tags);
		expect(status).not.toBe(0);
		expect(told).toContain("no target to scan");
	});
});
