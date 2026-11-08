import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { outsideLock } from "../../lockfile/contract.ts";
import { besideRelease, type OutsideModules } from "../contract.ts";

const grant = {
	name: "@x/grant",
	version: "1.2.0",
	integrity: `sha512-${"A".repeat(86)}==`,
	dependencies: { "jose-lite": "^1.0.0" },
	optionalDependencies: {},
	peerDependencies: {
		"@o3co/auth-provider-oauth": "^0.19.0",
		"@o3co/auth-provider-identity": "^0.19.0",
		zod: "^4.6.0",
	},
	peerDependenciesMeta: {},
};
const outside: OutsideModules = {
	modules: [grant],
	registries: { default: "https://registry.npmjs.org" },
};
/** As the release records it: each bundle's integrity, and zod's. */
const integrity = {
	"@o3co/auth-provider-identity": "sha512-IDENTITY",
	"@o3co/auth-provider-oauth": "sha512-OAUTH",
	"@o3co/auth-provider-other": "sha512-OTHER",
	zod: "sha512-ZOD",
};
const app = {
	dependencies: { "@o3co/auth-provider-oauth": "0.19.0", "@x/grant": "1.2.0" },
	version: "0.19.0",
	zod: "4.6.7",
	integrity,
};

describe("what an app beside packages outside the release is given", () => {
	it("is given nothing where it composes none", () => {
		for (const none of [
			undefined,
			{ modules: [], registries: { default: "https://registry.npmjs.org" } },
		]) {
			expect(besideRelease(none, app)).toEqual({
				files: {},
				image: undefined,
				guide: "",
				index: "",
				comesWith: expect.any(String),
				scripts: true,
				install: "`pnpm install`",
			});
		}
	});

	it("records each package and the registries, and ships the check bundled with what it uses, adding no dependency", () => {
		const beside = besideRelease(outside, app);
		expect(JSON.parse(beside.files["outside-modules.json"] as string)).toEqual({
			modules: [grant],
			registries: outside.registries,
			held: {
				"@o3co/auth-provider-identity": "sha512-IDENTITY",
				"@o3co/auth-provider-oauth": "sha512-OAUTH",
				zod: "sha512-ZOD",
			},
		});
		expect(beside.files["scripts/check-outside.mjs"]).toBe(
			readFileSync(outsideLock.script, "utf8"),
		);
		expect(beside).not.toHaveProperty("dependencies");
	});

	it("refuses a record whose fields are not a package name, version and integrity: they go into the guide's table", () => {
		for (const field of [
			{ name: "@x/gr`ant" },
			{ version: "1.2.0|x" },
			// A version the script would read as another, and an integrity cut short.
			{ version: "1.2.0+build" },
			{ integrity: "sha512-AAAA" },
			{ integrity: "sha512-AA\n| injected |" },
		]) {
			expect(() => besideRelease({ ...outside, modules: [{ ...grant, ...field }] }, app)).toThrow(
				"its record is not a package name, version and integrity",
			);
		}
	});

	it("holds every bundle of the release it depends on, or a package outside names as a peer, and zod to one version", () => {
		const settings = parse(besideRelease(outside, app).files["pnpm-workspace.yaml"] as string);
		expect(settings.overrides).toEqual({
			"@o3co/auth-provider-identity": "0.19.0",
			"@o3co/auth-provider-oauth": "0.19.0",
			zod: "4.6.7",
		});
	});

	it("says of an app beside a package outside that it has no scripts, whatever the package", () => {
		expect(besideRelease(outside, app).scripts).toBe(false);
		const plain = { ...outside, modules: [{ ...grant, peerDependencies: {} }] };
		expect(besideRelease(plain, app).scripts).toBe(false);
	});

	it("says of the guide's start to install as its section says", () => {
		const { install, guide } = besideRelease(outside, app);
		expect(install).toContain("`## Packages outside this release`");
		expect(guide).toContain("## Packages outside this release");
	});

	it("installs no version published within the last day, but the release's and those let through by name and version", () => {
		const fresh = besideRelease({ ...outside, fresh: ["@x/grant"] }, app).files[
			"pnpm-workspace.yaml"
		] as string;
		expect(parse(fresh).minimumReleaseAge).toBe(1440);
		expect(parse(fresh).minimumReleaseAgeExclude).toEqual([
			"@o3co/auth-provider-identity",
			"@o3co/auth-provider-oauth",
			"@x/grant@1.2.0",
		]);
		expect(
			parse(besideRelease(outside, app).files["pnpm-workspace.yaml"] as string)
				.minimumReleaseAgeExclude,
		).not.toContain("@x/grant@1.2.0");
	});

	it("checks the lockfile in the image's install stage, with what it checks against", () => {
		const { image } = besideRelease(outside, app);
		expect(image).toEqual({
			copy: ["outside-modules.json", "scripts/check-outside.mjs"],
			check: "node scripts/check-outside.mjs",
		});
	});

	it("tells the guide and the agents' index which packages lie outside the release, and what to run", () => {
		const { guide, index } = besideRelease(outside, app);
		expect(guide).toContain("## Packages outside this release");
		expect(guide).toContain(`| \`@x/grant\` | \`1.2.0\` | \`sha512-${"A".repeat(86)}==\` |`);
		const said = [
			"pnpm install --lockfile-only",
			"node scripts/check-outside.mjs",
			"pnpm install --frozen-lockfile --ignore-scripts",
		];
		expect(guide).toContain(said.join("\n"));
		expect(guide).not.toContain("pnpm check:outside");
		expect(guide).toContain("the overrides and `held` move together");
		expect(guide).toContain(
			"take `package.json`, this README, the overrides, `held`, `scripts/check-outside.mjs` and the `Dockerfile` from it",
		);
		expect(guide).toContain("Run the generator with `npx` from outside this directory");
		expect(guide).toContain("not covered by its conformance");
		expect(index).toContain("`outside-modules.json`");
	});

	it("tells the guide that `.bin` is not checked, that the app runs nothing through it, how each file runs, and what does use it", () => {
		const { guide } = besideRelease(outside, app);
		expect(guide).toContain("What pnpm links at `node_modules/.bin` is not checked");
		expect(guide).toContain("`pnpm start` and `pnpm run <entry>` fail");
		expect(guide).toContain(
			"an entry takes the same command and `APP_CONFIG`, naming `src/<entry>.ts`",
		);
		for (const route of [
			"a script you add",
			"`pnpm exec`",
			"`pnpm node`",
			"`pnpm <name>`",
			"`npx` or `pnpm dlx` run from this directory",
			"a `.bin/<cmd>` run by path",
			"a shell with `./node_modules/.bin` on PATH",
			"a package's build script once its build is approved",
		]) {
			expect(guide).toContain(route);
		}
		expect(guide).toContain("Do not approve a build pnpm stops at");
	});

	describe("a scope recorded with a registry of its own", () => {
		const scoped: OutsideModules = {
			...outside,
			registries: {
				default: "https://registry.npmjs.org",
				scopes: { "@x": "https://registry.x.example", "@a": "http://127.0.0.1:4873" },
			},
		};

		it("names each in the app's .npmrc, by its origin, and takes credentials in the image as a build secret", () => {
			const { files, image, guide } = besideRelease(scoped, app);
			expect(files[".npmrc"]).toBe(
				"@a:registry=http://127.0.0.1:4873/\n@x:registry=https://registry.x.example/\n",
			);
			expect(image).toEqual({
				copy: ["outside-modules.json", "scripts/check-outside.mjs", ".npmrc"],
				check: "node scripts/check-outside.mjs",
				mount: "--mount=type=secret,id=npmrc,target=/root/.npmrc",
			});
			expect(guide).toContain("`.npmrc` names the registry of each scope recorded");
			expect(guide).toContain("docker build --secret id=npmrc,src=$HOME/.npmrc");
		});

		it("gives an app with no such record none of it", () => {
			for (const none of [
				outside,
				{ ...outside, registries: { default: "https://r.example", scopes: {} } },
			]) {
				const { files, image, guide } = besideRelease(none, app);
				expect(files).not.toHaveProperty([".npmrc"]);
				expect(image).toEqual({
					copy: ["outside-modules.json", "scripts/check-outside.mjs"],
					check: "node scripts/check-outside.mjs",
				});
				expect(guide).not.toContain(".npmrc");
			}
		});

		it("refuses a record that is no scope and origin, telling neither, as an address may hold a secret", () => {
			for (const scopes of [
				{ "@x": "https://user:s3cret@registry.x.example" },
				{ "@x": "https://registry.x.example/path" },
				{ "@x": "file:///etc" },
				{ "@x": "https://${FOO}" },
				{ "@x": "https://$foo.example" },
				{ "@x": "https://r_x.example" },
				{ "@x\nregistry=https://evil.example": "https://registry.x.example" },
			]) {
				const given = { ...outside, registries: { default: "https://r.example", scopes } };
				expect(() => besideRelease(given, app)).toThrow(
					"a scoped registry's record is not a scope and an origin",
				);
			}
		});
	});

	it("says of the app's guide that only a package named comes, and says it for no other app", () => {
		const release =
			"What they need to run comes with them, and so do the wirings and bridges they come with.";
		expect(besideRelease(undefined, app).comesWith).toBe(release);
		const { comesWith } = besideRelease(outside, app);
		expect(comesWith).toContain("the wirings and bridges of the release's modules");
		expect(comesWith).toContain("each wiring and adapter outside it must be listed by name");
		expect(comesWith).toContain("boot refuses, naming the contract no module provides");
	});

	it("records the integrity the release recorded of every package it holds to one copy", () => {
		const record = JSON.parse(besideRelease(outside, app).files["outside-modules.json"] as string);
		expect(record.held).toEqual({
			"@o3co/auth-provider-identity": "sha512-IDENTITY",
			"@o3co/auth-provider-oauth": "sha512-OAUTH",
			zod: "sha512-ZOD",
		});
	});

	it("holds the closure of the release's packages it depends on, each bundle's bundles too, to one copy", () => {
		const closing = {
			...app,
			integrity: {
				...integrity,
				"@o3co/auth-provider-foundation": "sha512-FOUNDATION",
				"@o3co/auth-provider-second-factor": "sha512-SECOND",
			},
			bundles: {
				// From a dependency, through another alone, and a cycle ends.
				"@o3co/auth-provider-oauth": ["@o3co/auth-provider-second-factor"],
				"@o3co/auth-provider-second-factor": [
					"@o3co/auth-provider-foundation",
					"@o3co/auth-provider-oauth",
				],
				"@o3co/auth-provider-other": ["@o3co/auth-provider-other-still"],
			},
		};
		const closed = [
			"@o3co/auth-provider-foundation",
			"@o3co/auth-provider-identity",
			"@o3co/auth-provider-oauth",
			"@o3co/auth-provider-second-factor",
		];
		const { files } = besideRelease(outside, closing);
		const settings = parse(files["pnpm-workspace.yaml"] as string);
		expect(Object.keys(settings.overrides).sort()).toEqual([...closed, "zod"]);
		expect(settings.overrides["@o3co/auth-provider-second-factor"]).toBe("0.19.0");
		expect(settings.minimumReleaseAgeExclude).toEqual(closed);
		const { held } = JSON.parse(files["outside-modules.json"] as string);
		expect(Object.keys(held)).toEqual([...closed, "zod"]);
		expect(held["@o3co/auth-provider-second-factor"]).toBe("sha512-SECOND");
	});

	it("refuses a bundle of the closure the release records no integrity of", () => {
		const closing = {
			...app,
			bundles: { "@o3co/auth-provider-oauth": ["@o3co/auth-provider-unsealed"] },
		};
		expect(() => besideRelease(outside, closing)).toThrow(
			"@o3co/auth-provider-unsealed: held to one copy, but the release records no integrity of it",
		);
	});

	it("refuses a held package the release records no integrity of, and a release recording none", () => {
		const { integrity: _, ...unrecorded } = app;
		expect(() => besideRelease(outside, unrecorded)).toThrow(
			"@o3co/auth-provider-identity, @o3co/auth-provider-oauth, zod: held to one copy, but the release records no integrity of it",
		);
		expect(() =>
			besideRelease(outside, {
				...app,
				integrity: { "@o3co/auth-provider-oauth": "sha512-OAUTH" },
			}),
		).toThrow(
			"@o3co/auth-provider-identity, zod: held to one copy, but the release records no integrity of it",
		);
	});

	it("records each dependency let through though published within the last day, lets that version alone through, and names it in the guide and the index", () => {
		const jose = { name: "jose-lite", version: "1.4.0", integrity: `sha512-${"J".repeat(86)}==` };
		const beside = besideRelease({ ...outside, freshDependencies: [jose] }, app);
		expect(JSON.parse(beside.files["outside-modules.json"] as string).freshDependencies).toEqual([
			jose,
		]);
		expect(parse(beside.files["pnpm-workspace.yaml"] as string).minimumReleaseAgeExclude).toEqual([
			"@o3co/auth-provider-identity",
			"@o3co/auth-provider-oauth",
			"jose-lite@1.4.0",
		]);
		expect(beside.guide).toContain(
			`| \`jose-lite\` | \`1.4.0\` | \`sha512-${"J".repeat(86)}==\` |`,
		);
		expect(beside.index).toContain("`jose-lite@1.4.0`");
		const none = besideRelease(outside, app);
		expect(JSON.parse(none.files["outside-modules.json"] as string)).not.toHaveProperty(
			"freshDependencies",
		);
		expect(none.guide).not.toContain("within the last day, as a dependency");
	});

	it("refuses a dependency let through whose record is not a package name, version and integrity", () => {
		for (const jose of [
			{ name: "jose lite", version: "1.4.0", integrity: `sha512-${"J".repeat(86)}==` },
			{ name: "jose-lite", version: "1.4.0|x", integrity: `sha512-${"J".repeat(86)}==` },
			{ name: "jose-lite", version: "1.4.0", integrity: "md5-JOSE" },
		]) {
			expect(() => besideRelease({ ...outside, freshDependencies: [jose] }, app)).toThrow(
				`${jose.name}: its record is not a package name, version and integrity`,
			);
		}
	});

	it("refuses a package let through as fresh that it does not record", () => {
		expect(() => besideRelease({ ...outside, fresh: ["@x/other"] }, app)).toThrow(
			"@x/other: let through as fresh, but not recorded",
		);
	});
});
