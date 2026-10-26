import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { expect, it } from "vitest";

/** The scripts the publish job runs, which hold its token: what they load must be Node's alone. */
const entries = ["src/release/check-published.ts", "src/release-listed/listed.ts"].map((f) =>
	join(import.meta.dirname, "..", "..", "..", f),
);
const specifier =
	/(?:^|\n)\s*(?:import|export)\s[^"']*?from\s+["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

/** Every file the entries load, followed through relative imports, with each specifier it names. */
function loaded(from: readonly string[]) {
	const seen = new Map<string, string[]>();
	const todo = [...from];
	while (todo.length > 0) {
		const file = todo.pop() as string;
		if (seen.has(file)) continue;
		const named = [...readFileSync(file, "utf8").matchAll(specifier)].map(
			(m) => (m[1] ?? m[2]) as string,
		);
		seen.set(file, named);
		for (const s of named.filter((s) => s.startsWith("."))) todo.push(resolve(dirname(file), s));
	}
	return seen;
}

it("loads nothing but Node's own modules and the package's files where the release publishes", () => {
	const outside = [...loaded(entries)].flatMap(([file, named]) =>
		named.filter((s) => !s.startsWith(".") && !s.startsWith("node:")).map((s) => `${file}: ${s}`),
	);
	expect(outside).toEqual([]);
});
