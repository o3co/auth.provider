import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
import { buildBundles } from "../src/build.ts";
import type { Bundle } from "../src/contract.ts";

// Each test compiles bundles with TypeScript, which takes seconds when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

let root = "";
const write = (path: string, text: string) => {
	mkdirSync(dirname(join(root, path)), { recursive: true });
	writeFileSync(join(root, path), text);
};
const manifest = (name: string, more: object = {}) =>
	JSON.stringify({ name, private: true, type: "module", ...more });

/** Two shipped bundles and an unshipped one, written as a workspace places them. */
beforeAll(() => {
	root = mkdtempSync(join(tmpdir(), "distribution-"));
	write(
		"modules/base/package.json",
		JSON.stringify({ private: false, description: "The base.", keywords: ["kernel"] }),
	);
	write(
		"modules/base/kernel/package.json",
		manifest("@mod/kernel", {
			exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
			dependencies: { zod: "4.6.5" },
		}),
	);
	write(
		"modules/base/kernel/src/contract.ts",
		`export const kernel = (n: number): number => n + 1;\n`,
	);
	write(
		"modules/base/kernel/src/module.ts",
		`import { kernel } from "./contract.ts";\nexport default kernel;\n`,
	);
	write("modules/base/kernel/config.example", "kernel {}\n");
	write("modules/base/kernel/trial.conf", "kernel {}\n");
	write(
		"modules/feature/package.json",
		JSON.stringify({
			private: false,
			description: "The feature.",
			index: "index.json",
			entrances: {
				"@o3co/create-feature": {
					description: "Make a feature app.",
					keywords: ["create-app"],
					bin: "create-feature",
					runs: "@mod/app",
				},
			},
		}),
	);
	write(
		"modules/feature/app/package.json",
		manifest("@mod/app", {
			kind: "feature",
			exports: { ".": "./src/contract.ts" },
			dependencies: { "@mod/kernel": "workspace:*" },
		}),
	);
	write(
		"modules/feature/app/src/contract.ts",
		`import { kernel } from "@mod/kernel";\nimport { twice } from "./helper.ts";\nexport const app = (n: number): number => twice(kernel(n));\n`,
	);
	write(
		"modules/feature/app/src/helper.ts",
		`export const twice = (n: number): number => n * 2;\n`,
	);
	write("modules/feature/app/src/test/app.test.ts", `export const left = "out";\n`);
	write("modules/feature/app/README.md", "# app\n");
});
afterAll(() => rmSync(root, { recursive: true, force: true }));

const bundles = (): Bundle[] => [
	{
		dir: join(root, "modules/base"),
		shipped: true,
		members: [
			{ name: "@mod/kernel", dir: join(root, "modules/base/kernel"), dependencies: ["zod"] },
		],
	},
	{
		dir: join(root, "modules/feature"),
		shipped: true,
		members: [
			{ name: "@mod/app", dir: join(root, "modules/feature/app"), dependencies: ["@mod/kernel"] },
		],
	},
];

it("builds each shipped bundle: its members' files built and named publicly, their other files, and its manifest", () => {
	const out = join(root, "dist");
	const { built, problems } = buildBundles({
		bundles: bundles(),
		release: { version: "0.18.0" },
		out,
	});
	expect(problems).toEqual([]);
	expect(built).toEqual([
		"@o3co/auth-provider-base",
		"@o3co/auth-provider-feature",
		"@o3co/create-feature",
	]);
	const app = (path: string) => readFileSync(join(out, "feature/app", path), "utf8");
	expect(app("src/contract.js")).toContain(`from "@o3co/auth-provider-base/kernel"`);
	expect(app("src/contract.js")).toContain(`from "./helper.js"`);
	expect(app("src/contract.d.ts")).toContain("app: (n: number) => number");
	expect(app("README.md")).toBe("# app\n");
	expect(existsSync(join(out, "feature/app/src/test"))).toBe(false);
	expect(readFileSync(join(out, "base/kernel/config.example"), "utf8")).toBe("kernel {}\n");
	expect(existsSync(join(out, "base/kernel/trial.conf"))).toBe(false);
	const feature = JSON.parse(readFileSync(join(out, "feature/package.json"), "utf8"));
	expect(feature).toMatchObject({
		name: "@o3co/auth-provider-feature",
		version: "0.18.0",
		dependencies: { "@o3co/auth-provider-base": "0.18.0" },
		exports: { "./app": { types: "./app/src/contract.d.ts", default: "./app/src/contract.js" } },
	});
});

it("writes the index a bundle asks for: each shipped member's manifest, public names and section example", () => {
	const out = join(root, "dist-index");
	buildBundles({ bundles: bundles(), release: { version: "0.18.0" }, out });
	const index = JSON.parse(readFileSync(join(out, "feature/index.json"), "utf8"));
	expect(index.version).toBe("0.18.0");
	expect(index.packages).toEqual([
		{
			name: "@mod/app",
			package: "@o3co/auth-provider-feature",
			entry: "@o3co/auth-provider-feature/app",
			manifest: expect.objectContaining({ name: "@mod/app", kind: "feature" }),
		},
		{
			name: "@mod/kernel",
			package: "@o3co/auth-provider-base",
			entry: "@o3co/auth-provider-base/kernel",
			manifest: expect.objectContaining({ name: "@mod/kernel" }),
			fragment: "kernel {}\n",
		},
	]);
	expect(existsSync(join(out, "base/index.json"))).toBe(false);
});

it("builds an entrance a bundle declares: a package of its own name whose command calls the member's run", () => {
	const out = join(root, "dist-entrance");
	const { built } = buildBundles({ bundles: bundles(), release: { version: "0.18.0" }, out });
	expect(built).toContain("@o3co/create-feature");
	const entrance = JSON.parse(readFileSync(join(out, "create-feature/package.json"), "utf8"));
	expect(entrance).toEqual({
		name: "@o3co/create-feature",
		version: "0.18.0",
		description: "Make a feature app.",
		keywords: ["create-app"],
		type: "module",
		bin: { "create-feature": "./main.js" },
		dependencies: { "@o3co/auth-provider-feature": "0.18.0" },
	});
	expect(readFileSync(join(out, "create-feature/main.js"), "utf8")).toBe(
		`#!/usr/bin/env node\nimport { run } from "@o3co/auth-provider-feature/app";\n\nprocess.exitCode = await run(process.argv.slice(2));\n`,
	);
});

it("gives an entrance the workspace's license and engines, as a bundle has them", () => {
	const out = join(root, "dist-entrance-license");
	const release = { version: "0.18.0", license: "Apache-2.0", engines: { node: ">=24" } };
	buildBundles({ bundles: bundles(), release, out });
	const entrance = JSON.parse(readFileSync(join(out, "create-feature/package.json"), "utf8"));
	expect(entrance).toMatchObject({ license: "Apache-2.0", engines: { node: ">=24" } });
});

it("gives each bundle and entrance its own description, and the workspace's keywords then its own", () => {
	const out = join(root, "dist-about");
	const release = { version: "0.18.0", keywords: ["oauth2", "kernel"] };
	buildBundles({ bundles: bundles(), release, out });
	const read = (dir: string) => JSON.parse(readFileSync(join(out, dir, "package.json"), "utf8"));
	expect(read("base")).toMatchObject({ description: "The base.", keywords: ["oauth2", "kernel"] });
	expect(read("feature")).toMatchObject({
		description: "The feature.",
		keywords: ["oauth2", "kernel"],
	});
	expect(read("create-feature")).toMatchObject({
		description: "Make a feature app.",
		keywords: ["oauth2", "kernel", "create-app"],
	});
});

it("refuses a shipped bundle, or an entrance, that states no description", () => {
	const declared = join(root, "modules/feature/package.json");
	const before = readFileSync(declared, "utf8");
	const { description: _, ...rest } = JSON.parse(before);
	const entrance = rest.entrances["@o3co/create-feature"];
	writeFileSync(declared, JSON.stringify(rest));
	try {
		const { built, problems } = buildBundles({
			bundles: bundles(),
			release: { version: "0.18.0" },
			out: join(root, "dist-undescribed"),
		});
		expect(problems).toEqual(["@o3co/auth-provider-feature: states no description"]);
		expect(built).toEqual(["@o3co/auth-provider-base"]);
		const { description: __, ...bare } = entrance;
		writeFileSync(
			declared,
			JSON.stringify({
				...rest,
				description: "The feature.",
				entrances: { "@o3co/create-feature": bare },
			}),
		);
		const again = buildBundles({
			bundles: bundles(),
			release: { version: "0.18.0" },
			out: join(root, "dist-undescribed-entrance"),
		});
		expect(again.problems).toEqual(["@o3co/create-feature: states no description"]);
	} finally {
		writeFileSync(declared, before);
	}
});

it("puts the workspace's license file in each bundle and entrance, so any packer ships it", () => {
	const out = join(root, "dist-license-file");
	const license = join(root, "LICENSE");
	writeFileSync(license, "Apache License\nVersion 2.0\n");
	buildBundles({ bundles: bundles(), release: { version: "0.18.0" }, out, licenseFile: license });
	for (const dir of ["base", "feature", "create-feature"]) {
		expect(readFileSync(join(out, dir, "LICENSE"), "utf8"), dir).toBe(
			"Apache License\nVersion 2.0\n",
		);
	}
});

it("gives each bundle and entrance a README pointing at the repository, with the workspace's notice", () => {
	const out = join(root, "dist-readme");
	const release = {
		version: "0.18.0",
		repository: "https://github.com/o3co/auth.provider",
		notice: "Copyright 2026 Example Ltd. Licensed under the Apache License, Version 2.0.",
	};
	buildBundles({ bundles: bundles(), release, out });
	const feature = readFileSync(join(out, "feature/README.md"), "utf8");
	expect(feature).toContain("# @o3co/auth-provider-feature");
	expect(feature).toContain("0.18.0");
	expect(feature).toContain("https://github.com/o3co/auth.provider");
	expect(feature).toContain("`modules/feature`");
	expect(feature.trimEnd().endsWith(release.notice)).toBe(true);
	const entrance = readFileSync(join(out, "create-feature/README.md"), "utf8");
	expect(entrance).toContain("# @o3co/create-feature");
	expect(entrance.trimEnd().endsWith(release.notice)).toBe(true);
	const entranceManifest = JSON.parse(
		readFileSync(join(out, "create-feature/package.json"), "utf8"),
	);
	expect(entranceManifest.repository).toEqual({ type: "git", url: release.repository });
});

it("builds no bundle the workspace does not ship", () => {
	const out = join(root, "dist-shipped");
	const [base, feature] = bundles() as [Bundle, Bundle];
	const { built } = buildBundles({
		bundles: [base, { ...feature, shipped: false }],
		release: { version: "0.18.0" },
		out,
	});
	expect(built).toEqual(["@o3co/auth-provider-base"]);
	expect(existsSync(join(out, "feature"))).toBe(false);
});

it("tells what does not build, by file", () => {
	write("modules/base/kernel/src/broken.ts", `export const n: number = "not a number";\n`);
	write(
		"modules/base/kernel/package.json",
		manifest("@mod/kernel", {
			exports: {
				".": "./src/contract.ts",
				"./module": "./src/module.ts",
				"./broken": "./src/broken.ts",
			},
		}),
	);
	try {
		const { problems } = buildBundles({
			bundles: bundles(),
			release: { version: "0.18.0" },
			out: join(root, "dist-broken"),
		});
		expect(problems.some((p) => p.includes("broken.ts"))).toBe(true);
	} finally {
		rmSync(join(root, "modules/base/kernel/src/broken.ts"));
	}
});
