import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { integrityOf, tarballFileOf } from "../../packed/packed.ts";
import { takenFromRegistry } from "../fetch.ts";

/** A tarball as the registry holds one: `package/package.json`. */
function tarball(name: string, version: string): string {
	const at = mkdtempSync(join(tmpdir(), "fetch-"));
	mkdirSync(join(at, "package"));
	writeFileSync(join(at, "package", "package.json"), JSON.stringify({ name, version }));
	const file = join(at, "out.tgz");
	execFileSync("tar", ["-czf", file, "-C", at, "package"]);
	return file;
}
const version = "1.0.0";
const units = ["foundation", "oauth"].map((dir) => {
	const name = `@o3co/auth-provider-${dir}`;
	const file = tarball(name, version);
	return { dir, name, version, file, integrity: integrityOf(readFileSync(file)) };
});

/** An npm that answers `npm pack <name>@<version>` with the registry's tarball, each call kept. */
const registry = (calls: string[][]) => (command: string, args: readonly string[]) => {
	calls.push([command, ...args]);
	const [spec, , into] = [args[1] ?? "", args[2], args[3] ?? ""];
	const u = units.find((x) => `${x.name}@${x.version}` === spec);
	if (!u) return { status: 1, stderr: "E404" };
	copyFileSync(u.file, join(into, tarballFileOf(u.name, u.version)));
	return { status: 0, stderr: "" };
};

it("takes each package npm holds from the registry, all, some or none, no script run", () => {
	for (const taking of [units, units.slice(0, 1), []]) {
		const calls: string[][] = [];
		const into = mkdtempSync(join(tmpdir(), "fetched-"));
		const got = takenFromRegistry(taking, into, registry(calls));
		if ("problems" in got) throw new Error(got.problems.join("; "));
		expect([...got.given.keys()]).toEqual(taking.map((u) => u.dir));
		for (const u of taking)
			expect(integrityOf(readFileSync(got.given.get(u.dir) as string))).toBe(u.integrity);
		expect(calls.length).toBe(taking.length);
		for (const call of calls)
			expect(call).toEqual(expect.arrayContaining(["npm", "pack", "--ignore-scripts"]));
	}
});

it("refuses a tarball the registry gave whose bytes are not of the integrity it gave, and one it would not give", () => {
	const into = mkdtempSync(join(tmpdir(), "fetched-"));
	const wrong = [{ ...units[0], integrity: "sha512-other" }] as typeof units;
	expect(takenFromRegistry(wrong, into, registry([]))).toEqual({
		problems: [
			"@o3co/auth-provider-foundation@1.0.0: the registry's tarball is not of the integrity it gave",
		],
	});
	const absent = [{ ...units[0], name: "@o3co/auth-provider-none" }] as typeof units;
	expect(takenFromRegistry(absent, into, registry([]))).toEqual({
		problems: ["@o3co/auth-provider-none@1.0.0: not taken from the registry (E404)"],
	});
});
