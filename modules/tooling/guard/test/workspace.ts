import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Pkg } from "@mod/guard-imports";
import type { Budget } from "../src/contract.ts";

/** A budget for the tests' workspaces, close to the repository's. */
export const budget: Budget = {
	readRangeBytes: 200_000,
	sourceLines: 1500,
	testLines: 2000,
	contractValues: 12,
	commonContractValues: 20,
	contractMembers: 3,
	widerContractMembers: 5,
	widerSurfaceKinds: ["common", "foundation"],
	dependencies: 10,
	cardLines: 60,
	cardBytes: 6500,
	narrowCardFanIn: 5,
	narrowCardLines: 45,
	cardItemBytes: 500,
	countedFixtureFile: "(^|/)test/fixtures/",
	dependencyCardBytes: 40_000,
	commentShare: 0.1,
	commentFloor: 4,
	laidOutValues: 2,
	testFile: "(^|/)test/|\\.test\\.ts$",
	fixtureFile: "(^|/)test/fixtures/|\\.vectors\\.ts$",
	commonKind: "common",
	runtimeFromKernel: ["foundation", "capability", "feature", "adapter"],
	kindOrder: [
		["common"],
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
export const root = mkdtempSync(join(tmpdir(), "guard-"));

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
