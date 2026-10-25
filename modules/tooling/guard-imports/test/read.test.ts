import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { readWorkspace } from "../src/contract.ts";

// pnpm is asked for the workspace's packages, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

it("leaves the root out, the root named by a link to it too", () => {
	const at = mkdtempSync(join(tmpdir(), "read-workspace-"));
	const root = join(at, "real");
	mkdirSync(join(root, "packages", "a"), { recursive: true });
	writeFileSync(join(root, "pnpm-workspace.yaml"), 'packages:\n  - "packages/*"\n');
	writeFileSync(join(root, "package.json"), '{ "name": "root", "private": true }\n');
	writeFileSync(join(root, "packages", "a", "package.json"), '{ "name": "@t/a" }\n');
	const link = join(at, "link");
	symlinkSync(root, link);
	for (const named of [root, link]) {
		expect(readWorkspace(named).map((p) => p.name)).toEqual(["@t/a"]);
	}
});
