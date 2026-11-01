import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Rules } from "../src/scope.ts";
import type { Pkg } from "../src/workspace.ts";

/** The rules the tests' workspaces are read under, as the repository's. */
export const budget: Rules = {
	testFile: "(^|/)test/|\\.test\\.ts$",
	commonKind: "common",
	runtimeFromKernel: ["foundation", "capability", "feature", "adapter"],
	widerSurfaceKinds: ["common", "foundation"],
	kindOrder: [
		["common", "protocol"],
		["foundation"],
		["capability"],
		["feature"],
		["adapter"],
		["assembly", "wiring", "verification"],
	],
	verificationKind: "verification",
	productKinds: ["foundation", "capability", "feature", "adapter", "wiring"],
	wiringKind: "wiring",
	capabilityKind: "capability",
	capabilityBlind: ["feature"],
	adapterKind: "adapter",
	featureKind: "feature",
};

/** Where the tests' packages are written. */
export const root = mkdtempSync(join(tmpdir(), "guard-imports-"));

/** A package written under a fresh directory, with its files and manifest. */
export function pkg(
	name: string,
	files: Record<string, string>,
	manifest: Pkg["manifest"] = { exports: { ".": "./src/contract.ts" } },
	kind = "feature",
): Pkg {
	const dir = join(root, name.replace("/", "_"));
	for (const [file, text] of Object.entries(files)) {
		mkdirSync(join(dir, file, ".."), { recursive: true });
		writeFileSync(join(dir, file), text);
	}
	return {
		name,
		dir,
		manifest: { kind, ...manifest },
		card: `# ${name}\n`,
		files: Object.keys(files),
	};
}
