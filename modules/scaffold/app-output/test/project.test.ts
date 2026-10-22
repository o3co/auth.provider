import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { manifestOf } from "../src/project.ts";

it("pins the pnpm the workspace builds with, so the lockfile reads alike in the image", async () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..", "package.json");
	const workspace = JSON.parse(await readFile(root, "utf8")) as { packageManager: string };
	const app = JSON.parse(manifestOf("node src/main.ts", {})) as { packageManager: string };
	expect(app.packageManager).toBe(workspace.packageManager);
});
