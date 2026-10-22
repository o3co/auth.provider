import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { capabilityBlind, kindOrder, kinds, mayNeed } from "../src/contract.ts";

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

it("orders every kind once, from the bottom up", () => {
	const ordered = kindOrder.flat();
	expect(new Set(ordered).size).toBe(ordered.length);
	expect([...ordered].sort()).toEqual(Object.values(kinds).sort());
});

it("lets a kind need its own level and those below, never one above", () => {
	expect(mayNeed(kinds.feature, kinds.foundation)).toBe(true);
	expect(mayNeed(kinds.feature, kinds.feature)).toBe(true);
	expect(mayNeed(kinds.adapter, kinds.feature)).toBe(true);
	expect(mayNeed(kinds.wiring, kinds.capability)).toBe(true);
	expect(mayNeed(kinds.foundation, kinds.feature)).toBe(false);
	expect(mayNeed(kinds.feature, kinds.adapter)).toBe(false);
	expect(mayNeed(kinds.feature, kinds.wiring)).toBe(false);
});

it("keeps a capability-blind kind off a capability, though it sits below", () => {
	for (const blind of capabilityBlind) expect(mayNeed(blind, kinds.capability)).toBe(false);
	expect(mayNeed(kinds.adapter, kinds.capability)).toBe(true);
});

it("lets nothing need, or be needed by, a word that is no kind", () => {
	expect(mayNeed("plugin", kinds.common)).toBe(false);
	expect(mayNeed(kinds.feature, "plugin")).toBe(false);
});
