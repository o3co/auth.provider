import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { integrityOf, type Packed, packedOf, sealed, zodOf } from "../src/seal.ts";

/** A tarball as pnpm packs one: `package/package.json` and a file. */
function tarball(name: string, version: string): string {
	const at = mkdtempSync(join(tmpdir(), "seal-"));
	mkdirSync(join(at, "package"));
	writeFileSync(join(at, "package", "package.json"), JSON.stringify({ name, version }));
	writeFileSync(join(at, "package", "index.js"), "export {};\n");
	const file = join(at, "out.tgz");
	execFileSync("tar", ["-czf", file, "-C", at, "package"]);
	return file;
}

const lockWith = (zods: Record<string, string | undefined>) =>
	`lockfileVersion: '9.0'\n\npackages:\n\n${Object.entries(zods)
		.map(
			([version, integrity]) =>
				`  zod@${version}:\n    resolution: {${integrity ? `integrity: ${integrity}` : "tarball: x"}}\n`,
		)
		.join("\n")}`;

it("reads a tarball's name and version, and gives the integrity npm records of its bytes", () => {
	const file = tarball("@o3co/auth-provider-oauth", "0.19.0");
	const packed = packedOf(file);
	expect(packed).toEqual({
		name: "@o3co/auth-provider-oauth",
		version: "0.19.0",
		integrity: integrityOf(readFileSync(file)),
	});
	expect(packed.integrity).toMatch(/^sha512-[A-Za-z0-9+/]+=*$/);
});

it("reads the one zod the lockfile holds, and refuses none, two, or one without a sha512 integrity", () => {
	expect(zodOf(lockWith({ "4.6.7": "sha512-AAAA" }))).toEqual({
		version: "4.6.7",
		integrity: "sha512-AAAA",
	});
	expect(zodOf(lockWith({}))).toBe("the lockfile holds 0 versions of zod, where one is recorded");
	expect(zodOf(lockWith({ "4.6.7": "sha512-AAAA", "4.6.8": "sha512-BBBB" }))).toBe(
		"the lockfile holds 2 versions of zod, where one is recorded",
	);
	expect(zodOf(lockWith({ "4.6.7": undefined }))).toBe(
		"the lockfile holds no sha512 integrity of zod",
	);
});

it("reads the workspace's own lockfile, whose zod an app is held to", () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..");
	const zod = zodOf(readFileSync(join(root, "pnpm-lock.yaml"), "utf8"));
	expect(typeof zod === "string" ? zod : zod.version).toBe("4.6.7");
});

describe("sealing the index", () => {
	const index = { version: "0.19.0", packages: [] };
	const packed = (name: string, version = "0.19.0"): Packed => ({
		name,
		version,
		integrity: `sha512-${name.length}`,
	});
	const zod = { version: "4.6.7", integrity: "sha512-ZZZZ" };
	const bundles = ["@o3co/auth-provider-oauth", "@o3co/auth-provider-foundation"];

	it("adds every bundle's integrity and zod's, keeping what the index holds", () => {
		const result = sealed(
			index,
			bundles,
			bundles.map((b) => packed(b)),
			zod,
		);
		expect(result).toEqual({
			index: {
				version: "0.19.0",
				packages: [],
				integrity: {
					"@o3co/auth-provider-foundation": "sha512-30",
					"@o3co/auth-provider-oauth": "sha512-25",
				},
				zod,
			},
		});
	});

	it("refuses a bundle without its tarball, a tarball of another version or of no bundle, and no zod", () => {
		expect(sealed(index, bundles, [packed("@o3co/auth-provider-oauth")], zod)).toEqual({
			problems: ["@o3co/auth-provider-foundation: 0 tarballs, where one is sealed"],
		});
		expect(
			sealed(
				index,
				bundles,
				[packed(bundles[0] as string, "0.18.2"), packed(bundles[1] as string)],
				zod,
			),
		).toEqual({
			problems: ["@o3co/auth-provider-oauth: its tarball is 0.18.2, where the release is 0.19.0"],
		});
		expect(
			sealed(
				index,
				bundles,
				[...bundles.map((b) => packed(b)), packed("@o3co/auth-provider-scaffold")],
				zod,
			),
		).toEqual({
			problems: ["@o3co/auth-provider-scaffold: a tarball of no bundle the index is sealed over"],
		});
		expect(
			sealed(
				index,
				bundles,
				bundles.map((b) => packed(b)),
				"the lockfile holds no sha512 integrity of zod",
			),
		).toEqual({
			problems: ["the lockfile holds no sha512 integrity of zod"],
		});
	});
});
