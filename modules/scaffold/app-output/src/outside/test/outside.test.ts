import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { outsideLock } from "../../lockfile/contract.ts";
import { besideRelease, type OutsideModules } from "../contract.ts";

const grant = {
	name: "@x/grant",
	version: "1.2.0",
	integrity: "sha512-AAAA",
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
const app = {
	dependencies: { "@o3co/auth-provider-oauth": "0.19.0", "@x/grant": "1.2.0" },
	version: "0.19.0",
	zod: "4.6.7",
};

describe("what an app beside packages outside the release is given", () => {
	it("is given nothing where it composes none", () => {
		for (const none of [
			undefined,
			{ modules: [], registries: { default: "https://registry.npmjs.org" } },
		]) {
			expect(besideRelease(none, app)).toEqual({
				files: {},
				scripts: {},
				image: undefined,
				guide: "",
				index: "",
			});
		}
	});

	it("records each package and the registries, and ships the check bundled with what it uses, adding no dependency", () => {
		const beside = besideRelease(outside, app);
		expect(JSON.parse(beside.files["outside-modules.json"] as string)).toEqual({
			modules: [grant],
			registries: outside.registries,
		});
		expect(beside.files["scripts/check-outside.mjs"]).toBe(
			readFileSync(outsideLock.script, "utf8"),
		);
		expect(beside.scripts).toEqual({ "check:outside": "node scripts/check-outside.mjs" });
		expect(beside).not.toHaveProperty("dependencies");
	});

	it("refuses a record whose fields are not a package name, version and integrity: they go into the guide's table", () => {
		for (const field of [
			{ name: "@x/gr`ant" },
			{ version: "1.2.0|x" },
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
			after: "pnpm check:outside",
		});
	});

	it("tells the guide and the agents' index which packages lie outside the release, and what to run", () => {
		const { guide, index } = besideRelease(outside, app);
		expect(guide).toContain("## Packages outside this release");
		expect(guide).toContain("| `@x/grant` | `1.2.0` | `sha512-AAAA` |");
		expect(guide).toContain("pnpm check:outside");
		expect(guide).toContain("not covered by its conformance");
		expect(index).toContain("`outside-modules.json`");
	});

	it("records the integrity the release recorded of every package it holds to one copy, where the release records them", () => {
		const integrity = {
			"@o3co/auth-provider-identity": "sha512-IDENTITY",
			"@o3co/auth-provider-oauth": "sha512-OAUTH",
			"@o3co/auth-provider-other": "sha512-OTHER",
			zod: "sha512-ZOD",
		};
		const record = JSON.parse(
			besideRelease(outside, { ...app, integrity }).files["outside-modules.json"] as string,
		);
		expect(record.held).toEqual({
			"@o3co/auth-provider-identity": "sha512-IDENTITY",
			"@o3co/auth-provider-oauth": "sha512-OAUTH",
			zod: "sha512-ZOD",
		});
		expect(
			JSON.parse(besideRelease(outside, app).files["outside-modules.json"] as string),
		).not.toHaveProperty("held");
	});

	it("refuses a held package the release records no integrity of", () => {
		expect(() =>
			besideRelease(outside, {
				...app,
				integrity: { "@o3co/auth-provider-oauth": "sha512-OAUTH" },
			}),
		).toThrow(
			"@o3co/auth-provider-identity, zod: held to one copy, but the release records no integrity of it",
		);
	});

	it("refuses a package let through as fresh that it does not record", () => {
		expect(() => besideRelease({ ...outside, fresh: ["@x/other"] }, app)).toThrow(
			"@x/other: let through as fresh, but not recorded",
		);
	});
});
