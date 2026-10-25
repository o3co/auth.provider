import { describe, expect, it } from "vitest";
import { type Bom, coverageProblems, insideBom, npmNamed } from "../boms.ts";

const hex = "ab".repeat(64);
const integrity = `sha512-${Buffer.from(hex, "hex").toString("base64")}`;
const local = (name: string, version: string) => {
	const file = `${name.replace("@", "").replace("/", "-")}-${version}.tgz`;
	// As pnpm writes it: the scope's `@` encoded, the path given to the tarball in `vcs_url`.
	const ref = `pkg:npm/${name.replace("@", "%40")}@${version}?vcs_url=${encodeURIComponent(`file:../tarballs/${file}`)}`;
	return {
		type: "library",
		name: name.split("/")[1] as string,
		group: name.split("/")[0] as string,
		version,
		purl: ref,
		"bom-ref": ref,
		externalReferences: [
			{
				type: "distribution",
				url: `file:../tarballs/${file}`,
				hashes: [{ alg: "SHA-512", content: hex }],
			},
		],
	};
};
/** A package of the scope this release does not pack, installed from the registry. */
const hocon = {
	type: "library",
	group: "@o3co",
	name: "ts.hocon",
	version: "1.14.3",
	purl: "pkg:npm/%40o3co/ts.hocon@1.14.3",
	"bom-ref": "pkg:npm/%40o3co/ts.hocon@1.14.3",
};
const zod = {
	type: "library",
	name: "zod",
	version: "4.6.7",
	purl: "pkg:npm/zod@4.6.7",
	"bom-ref": "pkg:npm/zod@4.6.7",
};
const bomOf = (components: Bom["components"], dependencies: Bom["dependencies"] = []): Bom => ({
	bomFormat: "CycloneDX",
	specVersion: "1.6",
	metadata: {
		component: { type: "library", name: "app", version: "0.0.0", "bom-ref": "pkg:npm/app@0.0.0" },
	},
	components,
	dependencies,
});
const packed = [{ name: "@o3co/auth-provider-oauth", version: "1.0.0", integrity }];

describe("the published names of the release's own components", () => {
	it("names each component this release packed by npm's purl and registry URL, its hash and every other component as they are", () => {
		const own = local("@o3co/auth-provider-oauth", "1.0.0");
		const named = npmNamed(
			bomOf(
				[own, zod, hocon],
				[
					{ ref: "pkg:npm/app@0.0.0", dependsOn: [own["bom-ref"]] },
					{ ref: own["bom-ref"], dependsOn: ["pkg:npm/zod@4.6.7"] },
				],
			),
			packed,
		);
		if ("problems" in named) throw new Error(named.problems.join("; "));
		const npm = "pkg:npm/%40o3co/auth-provider-oauth@1.0.0";
		expect(named.bom.components[0]).toMatchObject({
			purl: npm,
			"bom-ref": npm,
			externalReferences: [
				{
					type: "distribution",
					url: "https://registry.npmjs.org/@o3co/auth-provider-oauth/-/auth-provider-oauth-1.0.0.tgz",
					hashes: [{ alg: "SHA-512", content: hex }],
				},
			],
		});
		expect(named.bom.components[1]).toEqual(zod);
		expect(named.bom.components[2]).toEqual(hocon);
		expect(named.bom.dependencies).toEqual([
			{ ref: "pkg:npm/app@0.0.0", dependsOn: [npm] },
			{ ref: npm, dependsOn: ["pkg:npm/zod@4.6.7"] },
		]);
	});

	it("stops, renaming nothing, where a packed component's reference is not its tarball's purl", () => {
		const own = local("@o3co/auth-provider-oauth", "1.0.0");
		const { "bom-ref": _, ...unreferenced } = own;
		expect(npmNamed(bomOf([unreferenced as typeof own]), packed)).toEqual({
			problems: [
				expect.stringMatching(
					/@o3co\/auth-provider-oauth@1\.0\.0: its reference is not its tarball's purl \(none\)/,
				),
			],
		});
		const registryRef = { ...own, "bom-ref": "pkg:npm/%40o3co/auth-provider-oauth@1.0.0" };
		expect(npmNamed(bomOf([registryRef]), packed)).toEqual({
			problems: [
				expect.stringMatching(
					/its reference is not its tarball's purl \(pkg:npm\/%40o3co\/auth-provider-oauth@1\.0\.0\)/,
				),
			],
		});
	});

	it("stops, renaming nothing, where a component this release packed is not named by its tarball's path", () => {
		const own = local("@o3co/auth-provider-oauth", "1.0.0");
		const fromRegistry = {
			...own,
			purl: "pkg:npm/%40o3co/auth-provider-oauth@1.0.0",
			"bom-ref": "pkg:npm/%40o3co/auth-provider-oauth@1.0.0",
		};
		expect(npmNamed(bomOf([fromRegistry]), packed)).toEqual({
			problems: [
				expect.stringMatching(
					/@o3co\/auth-provider-oauth@1\.0\.0: its purl names no tarball this release packed/,
				),
			],
		});
		const otherFile = {
			...own,
			externalReferences: [{ type: "distribution", url: "https://elsewhere/x.tgz", hashes: [] }],
		};
		expect(npmNamed(bomOf([otherFile]), packed)).toEqual({
			problems: [expect.stringMatching(/its distribution URL is not its tarball's path/)],
		});
		expect(npmNamed(bomOf([local("@o3co/auth-provider-oauth", "9.9.9")]), packed)).toEqual({
			problems: [expect.stringMatching(/auth-provider-oauth@9\.9\.9: .*no tarball/)],
		});
	});
});

describe("what the operator's lists must hold of the release", () => {
	const npm = "pkg:npm/%40o3co/auth-provider-oauth@1.0.0";
	const own = {
		type: "library",
		name: "auth-provider-oauth",
		group: "@o3co",
		version: "1.0.0",
		"bom-ref": npm,
		externalReferences: [
			{ type: "distribution", url: "u", hashes: [{ alg: "SHA-512", content: hex }] },
		],
	};

	it("holds every tarball the release packed, by name, version and SHA-512, with what it depends on", () => {
		expect(coverageProblems([bomOf([own], [{ ref: npm, dependsOn: [] }])], packed)).toEqual([]);
	});

	it("names a tarball missing, of another hash, or with no dependency entry", () => {
		const two = [...packed, { name: "@o3co/create-auth-provider", version: "1.0.0", integrity }];
		expect(coverageProblems([bomOf([own], [{ ref: npm, dependsOn: [] }])], two)).toEqual([
			"@o3co/create-auth-provider@1.0.0: in no list",
		]);
		const other = {
			...own,
			externalReferences: [
				{ type: "distribution", url: "u", hashes: [{ alg: "SHA-512", content: "cd".repeat(64) }] },
			],
		};
		expect(coverageProblems([bomOf([other], [{ ref: npm, dependsOn: [] }])], packed)).toEqual([
			"@o3co/auth-provider-oauth@1.0.0: listed with another SHA-512 than its tarball's",
		]);
		expect(coverageProblems([bomOf([own])], packed)).toEqual([
			"@o3co/auth-provider-oauth@1.0.0: listed with no dependency entry",
		]);
	});
});

describe("the components a bundle holds inside", () => {
	const region = (name: string, version: string) =>
		`//#region ../../../node_modules/.pnpm/${name.replace("/", "+")}@${version}/node_modules/${name}/index.js\n//#endregion\n`;
	const scaffold = { name: "@o3co/auth-provider-scaffold", version: "1.0.0" };
	const declared = [
		{
			member: "app-output",
			file: "src/lockfile/check-outside.bundled.mjs",
			packages: ["semver", "yaml"],
		},
	];

	it("lists each declared package inside its bundle, at the version the bundle's regions name", () => {
		const files = new Map([
			[
				"package/app-output/src/lockfile/check-outside.bundled.mjs",
				region("semver", "7.8.5") + region("yaml", "2.9.1") + region("yaml", "2.9.1"),
			],
		]);
		const made = insideBom([{ ...scaffold, files }], declared);
		if ("problems" in made) throw new Error(made.problems.join("; "));
		expect(made.bom.components).toEqual([
			{
				type: "library",
				group: "@o3co",
				name: "auth-provider-scaffold",
				version: "1.0.0",
				purl: "pkg:npm/%40o3co/auth-provider-scaffold@1.0.0",
				"bom-ref": "pkg:npm/%40o3co/auth-provider-scaffold@1.0.0",
				components: [
					{
						type: "file",
						name: "app-output/src/lockfile/check-outside.bundled.mjs",
						"bom-ref":
							"pkg:npm/%40o3co/auth-provider-scaffold@1.0.0#app-output/src/lockfile/check-outside.bundled.mjs",
						components: [
							{
								type: "library",
								name: "semver",
								version: "7.8.5",
								purl: "pkg:npm/semver@7.8.5",
								"bom-ref": "pkg:npm/semver@7.8.5",
							},
							{
								type: "library",
								name: "yaml",
								version: "2.9.1",
								purl: "pkg:npm/yaml@2.9.1",
								"bom-ref": "pkg:npm/yaml@2.9.1",
							},
						],
					},
				],
			},
		]);
	});

	it("refuses a bundled file no manifest declares, a declared one missing, and a package inside it declares not", () => {
		const undeclared = new Map([
			["package/app-output/src/other.bundled.mjs", region("semver", "7.8.5")],
		]);
		expect(insideBom([{ ...scaffold, files: undeclared }], declared)).toEqual({
			problems: [
				"@o3co/auth-provider-scaffold: package/app-output/src/other.bundled.mjs is bundled, and no manifest's bundledInside declares it",
				"app-output/src/lockfile/check-outside.bundled.mjs: declared, and in no tarball",
			],
		});
		const more = new Map([
			[
				"package/app-output/src/lockfile/check-outside.bundled.mjs",
				region("semver", "7.8.5") + region("yaml", "2.9.1") + region("@scope/x", "1.0.0"),
			],
		]);
		expect(insideBom([{ ...scaffold, files: more }], declared)).toEqual({
			problems: [
				"app-output/src/lockfile/check-outside.bundled.mjs: holds @scope/x@1.0.0 inside, which its manifest's bundledInside does not declare",
			],
		});
	});

	it("refuses a declared bundle whose regions name none, or only some, of the packages declared inside it", () => {
		const file = "package/app-output/src/lockfile/check-outside.bundled.mjs";
		const unread = insideBom(
			[{ ...scaffold, files: new Map([[file, "// no region\n"]]) }],
			declared,
		);
		expect(unread).toEqual({
			problems: [
				"app-output/src/lockfile/check-outside.bundled.mjs: its regions name no semver, which its manifest's bundledInside declares inside it",
				"app-output/src/lockfile/check-outside.bundled.mjs: its regions name no yaml, which its manifest's bundledInside declares inside it",
			],
		});
		const some = insideBom(
			[{ ...scaffold, files: new Map([[file, region("semver", "7.8.5")]]) }],
			declared,
		);
		expect(some).toEqual({
			problems: [
				"app-output/src/lockfile/check-outside.bundled.mjs: its regions name no yaml, which its manifest's bundledInside declares inside it",
			],
		});
	});
});
