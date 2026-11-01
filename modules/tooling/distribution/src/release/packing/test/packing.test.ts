import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { integrityOf, tarballFileOf } from "../../../packed/packed.ts";
import { packWith } from "../packing.ts";

const version = "1.0.0";
const lockfile =
	"lockfileVersion: '9.0'\n\npackages:\n\n  zod@4.6.7:\n    resolution: {integrity: sha512-Z}\n";
const nameOf = (dir: string) =>
	dir === "entrance" ? "@o3co/create-auth-provider" : `@o3co/auth-provider-${dir}`;

/** `dist/bundles` as `pnpm bundles` builds it: a directory a package, the scaffold holding the index. */
function built() {
	const out = mkdtempSync(join(tmpdir(), "bundles-"));
	for (const dir of ["foundation", "oauth", "scaffold", "entrance"]) {
		mkdirSync(join(out, dir));
		writeFileSync(join(out, dir, "package.json"), JSON.stringify({ name: nameOf(dir), version }));
		writeFileSync(join(out, dir, "code.js"), `export const of = ${JSON.stringify(dir)};\n`);
	}
	writeFileSync(join(out, "scaffold", "index.json"), JSON.stringify({ version }));
	return out;
}
const order = {
	first: ["foundation", "oauth"],
	index: { dir: "scaffold", file: "index.json" },
	last: ["scaffold", "entrance"],
};

/** A pack as pnpm's: the built directory as `package/`, into the file npm names it. */
const packer = (out: string, into: string, packed: string[]) => (dir: string) => {
	packed.push(dir);
	const stage = mkdtempSync(join(tmpdir(), "stage-"));
	execFileSync("cp", ["-R", join(out, dir), join(stage, "package")]);
	const file = join(into, tarballFileOf(nameOf(dir), version));
	execFileSync("tar", ["-czf", file, "-C", stage, "package"]);
	return file;
};
/** A tarball as the registry holds it: other bytes than this pack's. */
function published(dir: string) {
	const stage = mkdtempSync(join(tmpdir(), "published-"));
	mkdirSync(join(stage, "package"));
	writeFileSync(
		join(stage, "package", "package.json"),
		JSON.stringify({ name: nameOf(dir), version, published: true }),
	);
	const file = join(stage, tarballFileOf(nameOf(dir), version));
	execFileSync("tar", ["-czf", file, "-C", stage, "package"]);
	return file;
}
const sealedIn = (out: string) =>
	JSON.parse(readFileSync(join(out, "scaffold", "index.json"), "utf8"));

it("seals the index over every bundle before it, those taken from the registry and those packed alike", () => {
	const out = built();
	const into = mkdtempSync(join(tmpdir(), "into-"));
	const packed: string[] = [];
	const taken = published("foundation");
	const result = packWith({
		out,
		order,
		lockfile,
		into,
		given: new Map([["foundation", taken]]),
		pack: packer(out, into, packed),
	});
	if ("problems" in result) throw new Error(result.problems.join("; "));
	expect(packed).toEqual(["oauth", "scaffold", "entrance"]);
	expect(result.sealedOver).toBe(2);
	const of = (dir: string) =>
		integrityOf(readFileSync(join(into, tarballFileOf(nameOf(dir), version))));
	// The index names the integrity of the very tarballs there, the taken one's as the registry holds it.
	expect(sealedIn(out).integrity).toEqual({
		"@o3co/auth-provider-foundation": of("foundation"),
		"@o3co/auth-provider-oauth": of("oauth"),
	});
	expect(of("foundation")).toBe(integrityOf(readFileSync(taken)));
	expect(result.tarballs.map((t) => t.split("/").at(-1))).toEqual(
		["foundation", "oauth", "scaffold", "entrance"].map((d) => tarballFileOf(nameOf(d), version)),
	);
});

it("packs and seals everything where nothing is given, and seals nothing where the published scaffold is", () => {
	const fresh = built();
	const into = mkdtempSync(join(tmpdir(), "into-"));
	const packed: string[] = [];
	const all = packWith({
		out: fresh,
		order,
		lockfile,
		into,
		given: new Map(),
		pack: packer(fresh, into, packed),
	});
	expect("tarballs" in all && all.sealedOver).toBe(2);
	expect(packed).toEqual(["foundation", "oauth", "scaffold", "entrance"]);

	const out = built();
	const again = mkdtempSync(join(tmpdir(), "into-"));
	const taken: string[] = [];
	const given = new Map(["foundation", "oauth", "scaffold"].map((d) => [d, published(d)]));
	const result = packWith({
		out,
		order,
		lockfile,
		into: again,
		given,
		pack: packer(out, again, taken),
	});
	if ("problems" in result) throw new Error(result.problems.join("; "));
	// Only the entrance is packed; the scaffold as published is copied, its index not sealed again.
	expect(taken).toEqual(["entrance"]);
	expect(result.sealedOver).toBe(0);
	expect(sealedIn(out)).toEqual({ version });
	expect(integrityOf(readFileSync(join(again, tarballFileOf(nameOf("scaffold"), version))))).toBe(
		integrityOf(readFileSync(given.get("scaffold") as string)),
	);
});

it("refuses the published scaffold given while a bundle its index seals over is not", () => {
	const out = built();
	const into = mkdtempSync(join(tmpdir(), "into-"));
	const given = new Map([["scaffold", published("scaffold")]]);
	expect(packWith({ out, order, lockfile, into, given, pack: packer(out, into, []) })).toEqual({
		problems: ["scaffold is given, but foundation, oauth, which its index seals over, not"],
	});
});
