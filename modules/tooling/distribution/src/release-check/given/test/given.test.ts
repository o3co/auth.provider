import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { packBuilt, tarballsToCheck } from "../given.ts";

it("checks the tarballs in the directory named, as the release will publish them, packing none", () => {
	const dir = mkdtempSync(join(tmpdir(), "given-"));
	for (const f of ["b-1.0.0.tgz", "a-1.0.0.tgz", "notes.txt"]) writeFileSync(join(dir, f), "");
	const pack = () => {
		throw new Error("packed though tarballs were given");
	};
	expect(tarballsToCheck(dir, pack, "/scratch")).toEqual({
		dir,
		tarballs: [join(dir, "a-1.0.0.tgz"), join(dir, "b-1.0.0.tgz")],
	});
});

it("packs the release itself where it is given none, and refuses a directory given with no tarball", () => {
	const into: string[] = [];
	const packed = tarballsToCheck(
		undefined,
		(at) => {
			into.push(at);
			return { tarballs: [join(at, "a-1.0.0.tgz")] };
		},
		"/scratch",
	);
	expect(into).toEqual(["/scratch/tarballs"]);
	expect(packed).toEqual({ dir: "/scratch/tarballs", tarballs: ["/scratch/tarballs/a-1.0.0.tgz"] });
	const empty = mkdtempSync(join(tmpdir(), "given-"));
	mkdirSync(join(empty, "x"));
	expect(tarballsToCheck(empty, () => ({ tarballs: [] }), "/scratch")).toEqual({
		problems: [`${empty}: holds no tarball to check`],
	});
});

it("builds the bundles only where it packs them: never for tarballs given, and packs nothing after a build with problems", () => {
	const done: string[] = [];
	const build = (problems: readonly string[]) => () => {
		done.push("build");
		return { problems };
	};
	const pack = (into: string) => {
		done.push(`pack ${into}`);
		return { tarballs: [join(into, "a-1.0.0.tgz")] };
	};
	const given = mkdtempSync(join(tmpdir(), "given-"));
	writeFileSync(join(given, "a-1.0.0.tgz"), "");
	tarballsToCheck(given, packBuilt(build([]), pack), "/scratch");
	expect(done).toEqual([]);
	tarballsToCheck(undefined, packBuilt(build([]), pack), "/scratch");
	expect(done).toEqual(["build", "pack /scratch/tarballs"]);
	done.length = 0;
	expect(tarballsToCheck(undefined, packBuilt(build(["unbuilt"]), pack), "/scratch")).toEqual({
		problems: ["unbuilt"],
	});
	expect(done).toEqual(["build"]);
});
