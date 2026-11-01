import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";

const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");

it("is registered by every vitest config of the workspace, so no run's tests go unreported", () => {
	const configs = execFileSync("git", ["ls-files", "*vitest*.config.*"], {
		cwd: root,
		encoding: "utf8",
	})
		.split("\n")
		.filter((f) => f !== "" && !f.includes("/test/fixtures/"));
	expect(configs).toContain("vitest.config.ts");
	const unregistered = configs.filter(
		(f) =>
			// Further reporters may follow it, such as a fault run's.
			!/reporters: \["default", evidenceReporter\(\)(\]|, )/.test(
				readFileSync(join(root, f), "utf8"),
			),
	);
	expect(unregistered).toEqual([]);
});
