import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { Application } from "typedoc";
import { describe, expect, it, vi } from "vitest";
import { buildVersion } from "../src/build.ts";
import { manifest, tree } from "./fixture.ts";

vi.setConfig({ testTimeout: 60_000 });

describe("a version's API built from the bundles", () => {
	it("names each module by its public import, one bundle's reaching the other's", async () => {
		const project = tree({
			"node_modules/@o3co/a/package.json": manifest("@o3co/a", {
				"./clock": { types: "./clock/contract.d.ts", default: "./clock/contract.js" },
			}),
			"node_modules/@o3co/a/clock/contract.d.ts":
				"/** What tells the time. */\nexport interface Clock {\n\tnow(): number;\n}\n",
			"node_modules/@o3co/b/package.json": manifest("@o3co/b", {
				"./timer": { types: "./timer/contract.d.ts", default: "./timer/contract.js" },
			}),
			"node_modules/@o3co/b/timer/contract.d.ts":
				'import type { Clock } from "@o3co/a/clock";\n/** Starts a timer on a clock. */\nexport declare function start(clock: Clock): void;\n',
		});
		const out = join(project, "site", "v0.19");
		await buildVersion({ project, out, version: "0.19.2" });
		const modules = readdirSync(join(out, "modules")).sort();
		expect(modules).toEqual(["_o3co_a_clock.html", "_o3co_b_timer.html"]);
		const timer = readFileSync(join(out, "modules", "_o3co_b_timer.html"), "utf8");
		expect(timer).toContain("@o3co/b/timer");
		expect(readFileSync(join(out, "index.html"), "utf8")).toContain("auth-provider API 0.19.2");
	});

	it("hands typedoc plain files, in one dir with no dir under it", async () => {
		// typedoc's glob path calls minimatch's matchOne, which the minimatch 11 the workspace resolves
		// (GHSA-g3hv-75wg-m249) removed: a glob, or a common root with a dir under it, would throw.
		const bootstrap = vi.spyOn(Application, "bootstrapWithPlugins");
		const project = tree({
			"node_modules/@o3co/a/package.json": manifest("@o3co/a", {
				"./clock": { types: "./clock/contract.d.ts", default: "./clock/contract.js" },
				"./timer": { types: "./timer/contract.d.ts", default: "./timer/contract.js" },
			}),
			"node_modules/@o3co/a/clock/contract.d.ts": "export interface Clock {\n\tnow(): number;\n}\n",
			"node_modules/@o3co/a/timer/contract.d.ts": "export declare function start(): void;\n",
		});
		await buildVersion({ project, out: join(project, "site", "v0.19"), version: "0.19.2" });
		const entryPoints = bootstrap.mock.calls[0]?.[0]?.entryPoints ?? [];
		bootstrap.mockRestore();
		expect(entryPoints).toHaveLength(2);
		for (const entry of entryPoints) {
			expect(entry, entry).not.toMatch(/[*?[\]{}!]/);
			expect(statSync(entry).isFile(), entry).toBe(true);
		}
		const roots = new Set(entryPoints.map((entry) => dirname(entry)));
		expect(roots.size).toBe(1);
		const [root = ""] = roots;
		expect(readdirSync(root, { withFileTypes: true }).every((found) => found.isFile())).toBe(true);
	});
});
