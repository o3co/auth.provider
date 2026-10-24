import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
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
});
