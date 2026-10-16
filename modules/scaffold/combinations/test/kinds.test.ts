import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { kinds } from "../src/contract.ts";

it("names each kind once, in one word", () => {
	const words = Object.values(kinds);
	expect(new Set(words).size).toBe(words.length);
	for (const word of words) expect(word).toMatch(/^[a-z]+$/);
});

it("names every kind a package of the workspace declares", () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..");
	const listed = JSON.parse(
		execFileSync("pnpm", ["ls", "-r", "--json", "--depth", "-1"], { cwd: root, encoding: "utf8" }),
	) as { path: string }[];
	const words: readonly string[] = Object.values(kinds);
	for (const { path } of listed.filter((entry) => entry.path !== root)) {
		const { name, kind } = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
		expect(words, name).toContain(kind);
	}
}, 60_000);
