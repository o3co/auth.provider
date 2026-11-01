import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { expect, it } from "vitest";

const dir = join(import.meta.dirname, "..");
const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as {
	readonly bundledInside?: Readonly<Record<string, readonly string[]>>;
};

const walk = (at: string): string[] =>
	readdirSync(at).flatMap((entry) => {
		if (entry === "node_modules") return [];
		const path = join(at, entry);
		return statSync(path).isDirectory() ? walk(path) : [relative(dir, path)];
	});

/** The packages a bundle holds inside, as its regions name the files they came from. */
const heldBy = (file: string) =>
	new Set(
		[
			...readFileSync(join(dir, file), "utf8").matchAll(
				/^\/\/#region .*?node_modules\/\.pnpm\/[^/]+\/node_modules\/((?:@[^/]+\/)?[^/]+)\//gm,
			),
		].map((m) => m[1]),
	);

it("declares every bundled file it ships, with each package from outside the bundle holds inside", () => {
	const bundled = walk(dir).filter((f) => f.endsWith(".bundled.mjs"));
	expect(bundled.length).toBeGreaterThan(0);
	expect(Object.keys(manifest.bundledInside ?? {}).sort()).toEqual(bundled.sort());
	for (const file of bundled) {
		expect([...heldBy(file)].sort(), file).toEqual(
			[...(manifest.bundledInside?.[file] ?? [])].sort(),
		);
	}
});
