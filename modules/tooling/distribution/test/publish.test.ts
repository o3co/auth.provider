import { describe, expect, it } from "vitest";
import {
	aboutOf,
	bundleManifest,
	type MemberManifest,
	publicNameOf,
	published,
} from "../src/publish.ts";

const member = (name: string, more: Partial<MemberManifest> = {}): MemberManifest => ({
	name: `@mod/${name}`,
	dir: name,
	exports: { ".": "./src/contract.ts", "./module": "./src/module.ts" },
	dependencies: {},
	...more,
});
/** Which bundle each member is in, as the workspace places them. */
const placed: Record<string, string> = {
	"@mod/kernel": "foundation",
	"@mod/http": "foundation",
	"@mod/tokens": "oauth",
	"@mod/authorize": "oauth",
};
const bundleOf = (name: string) => placed[name];

describe("public names", () => {
	it("names a bundle after its concern directory", () => {
		expect(publicNameOf("/repo/modules/oauth")).toBe("@o3co/auth-provider-oauth");
	});
});

describe("what a package says of itself", () => {
	it("is its own description, and the release's keywords then its own, each once", () => {
		const release = { version: "0.18.0", keywords: ["oauth2", "oidc"] };
		expect(aboutOf("p", { description: "D.", keywords: ["dpop", "oidc"] }, release)).toEqual({
			about: { description: "D.", keywords: ["oauth2", "oidc", "dpop"] },
		});
		expect(aboutOf("p", { description: "D." }, { version: "0.18.0" })).toEqual({
			about: { description: "D.", keywords: [] },
		});
	});

	it("refuses a package without a description, or whose keywords are not a list of words", () => {
		const release = { version: "0.18.0" };
		expect(aboutOf("p", {}, release)).toEqual({ problem: "p: states no description" });
		expect(aboutOf("p", { description: " " }, release)).toEqual({
			problem: "p: states no description",
		});
		expect(aboutOf("p", { description: "D.", keywords: "dpop" }, release)).toEqual({
			problem: "p: its keywords are not a list of words",
		});
	});
});

describe("a bundle's manifest", () => {
	it("says what the bundle is, its keywords only when it has some", () => {
		const members = [member("tokens")];
		const release = { version: "0.18.0" };
		const about = { description: "D.", keywords: ["oauth2"] };
		const made = bundleManifest({ dir: "/repo/modules/oauth", members, about }, release, bundleOf);
		expect("manifest" in made && made.manifest).toMatchObject(about);
		const bare = {
			dir: "/repo/modules/oauth",
			members,
			about: { description: "D.", keywords: [] },
		};
		const unworded = bundleManifest(bare, release, bundleOf);
		expect("manifest" in unworded && "keywords" in unworded.manifest).toBe(false);
	});

	it("offers each member's entries under its directory's name, built, with their types", () => {
		const made = bundleManifest(
			{ dir: "/repo/modules/oauth", members: [member("tokens"), member("authorize")] },
			{ version: "0.18.0", engines: { node: ">=24" } },
			bundleOf,
		);
		expect(made).toEqual({
			manifest: {
				name: "@o3co/auth-provider-oauth",
				version: "0.18.0",
				type: "module",
				engines: { node: ">=24" },
				exports: {
					"./tokens": { types: "./tokens/src/contract.d.ts", default: "./tokens/src/contract.js" },
					"./tokens/module": {
						types: "./tokens/src/module.d.ts",
						default: "./tokens/src/module.js",
					},
					"./authorize": {
						types: "./authorize/src/contract.d.ts",
						default: "./authorize/src/contract.js",
					},
					"./authorize/module": {
						types: "./authorize/src/module.d.ts",
						default: "./authorize/src/module.js",
					},
				},
				dependencies: {},
			},
		});
	});

	it("names the repository and the bundle's directory in it, for provenance", () => {
		const bundle = { dir: "/repo/modules/oauth", members: [member("tokens")] };
		const release = { version: "0.18.0", repository: "https://github.com/o3co/auth.provider" };
		const made = bundleManifest(bundle, release, bundleOf);
		expect("manifest" in made && made.manifest.repository).toEqual({
			type: "git",
			url: "https://github.com/o3co/auth.provider",
			directory: "modules/oauth",
		});
	});

	it("carries the workspace's license, and none where the workspace states none", () => {
		const bundle = { dir: "/repo/modules/oauth", members: [member("tokens")] };
		const licensed = bundleManifest(bundle, { version: "0.18.0", license: "Apache-2.0" }, bundleOf);
		expect("manifest" in licensed && licensed.manifest.license).toBe("Apache-2.0");
		const unlicensed = bundleManifest(bundle, { version: "0.18.0" }, bundleOf);
		expect("manifest" in unlicensed && "license" in unlicensed.manifest).toBe(false);
	});

	it("depends on other bundles at its own version, and on outside packages at the version its members state", () => {
		const made = bundleManifest(
			{
				dir: "/repo/modules/oauth",
				members: [
					member("tokens", {
						dependencies: {
							"@mod/kernel": "workspace:*",
							"@mod/authorize": "workspace:*",
							zod: "4.6.5",
						},
					}),
					member("authorize", {
						dependencies: { "@mod/http": "workspace:*", zod: "4.6.5", jose: "6.2.12" },
					}),
				],
			},
			{ version: "0.18.0" },
			bundleOf,
		);
		expect("manifest" in made && made.manifest.dependencies).toEqual({
			"@o3co/auth-provider-foundation": "0.18.0",
			jose: "6.2.12",
			zod: "4.6.5",
		});
	});

	it("offers the members' peers as optional, and a member's command, built", () => {
		const made = bundleManifest(
			{
				dir: "/repo/modules/scaffold",
				members: [
					member("create-app", {
						bin: { "create-app": "./src/main.ts" },
						peerDependencies: { vitest: "5.0.3" },
					}),
				],
			},
			{ version: "0.18.0" },
			bundleOf,
		);
		expect("manifest" in made && made.manifest).toMatchObject({
			bin: { "create-app": "./create-app/src/main.js" },
			peerDependencies: { vitest: "5.0.3" },
			peerDependenciesMeta: { vitest: { optional: true } },
		});
	});

	it("refuses members that state one outside package at two versions, naming both", () => {
		const made = bundleManifest(
			{
				dir: "/repo/modules/oauth",
				members: [
					member("tokens", { dependencies: { zod: "4.6.5" } }),
					member("authorize", { dependencies: { zod: "4.7.0" } }),
				],
			},
			{ version: "0.18.0" },
			bundleOf,
		);
		expect(made).toEqual({
			problems: ["oauth: zod at 4.6.5 (@mod/tokens) and 4.7.0 (@mod/authorize)"],
		});
	});
});

describe("built files", () => {
	const where = (name: string) =>
		({
			"@mod/kernel": { bundle: "foundation", dir: "kernel" },
			"@mod/tokens": { bundle: "oauth", dir: "tokens" },
		})[name];

	it("name each member by its bundle's public name and its directory, entry included", () => {
		const text = `import { a } from "@mod/kernel";\nimport t from '@mod/tokens/testing';\nexport * from "@mod/kernel";`;
		expect(published(text, where, "js")).toEqual({
			text: `import { a } from "@o3co/auth-provider-foundation/kernel";\nimport t from '@o3co/auth-provider-oauth/tokens/testing';\nexport * from "@o3co/auth-provider-foundation/kernel";`,
			unknown: [],
		});
	});

	it("rename only what is imported, never a member's name a module holds as data", () => {
		const text = `import "@mod/kernel";\nconst kernel = "@mod/kernel";\nconst later = await import("@mod/tokens");\nconst listed = ['@mod/tokens'];`;
		expect(published(text, where, "js").text).toBe(
			`import "@o3co/auth-provider-foundation/kernel";\nconst kernel = "@mod/kernel";\nconst later = await import("@o3co/auth-provider-oauth/tokens");\nconst listed = ['@mod/tokens'];`,
		);
	});

	it("point a declaration's own imports at the built files, and tell a member it does not know", () => {
		const text = `import type { A } from "./a.ts";\nexport declare const b: import("../b.ts").B;\nimport { c } from "@mod/nowhere";`;
		expect(published(text, where, "d.ts")).toEqual({
			text: `import type { A } from "./a.js";\nexport declare const b: import("../b.js").B;\nimport { c } from "@mod/nowhere";`,
			unknown: ["@mod/nowhere"],
		});
	});
});
