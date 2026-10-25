import { readFileSync } from "node:fs";
import { expect, it, vi } from "vitest";
import { root } from "../../../test/root.ts";
import {
	auditIndexIn,
	cardLine,
	cardsFile,
	cardsOf,
	dependenciesFile,
	dependenciesOf,
	type Entry,
} from "../audit-index.ts";

vi.setConfig({ testTimeout: 60_000 });

const entry = (over: Partial<Entry> & Pick<Entry, "name" | "dir">): Entry => ({
	kind: "feature",
	line: "Does one thing.",
	internal: [],
	dependsOn: [],
	...over,
});

it("takes a card's line from its opening paragraph, or else its first responsibility", () => {
	expect(cardLine("# a\n\nWires `b` to `c`.\nAnd more.\n\n## Depends on\n")).toBe(
		"Wires `b` to `c`. And more.",
	);
	expect(cardLine("# a\n\nInternal module of `b`: holding a login.\n\n## Offers\n")).toBe(
		"holding a login.",
	);
	expect(
		cardLine("# a\n\n## Responsibilities\n- Reads each fragment.\n  - A detail.\n- Maps.\n"),
	).toBe("Reads each fragment.");
	expect(cardLine("# a\n\n## Offers\n- Something.\n")).toBeUndefined();
});

it("lists each package's card by its directory, its internal modules beneath it", () => {
	const listed = cardsOf([
		entry({ name: "@mod/b", dir: "modules/oauth/b", line: "Grants." }),
		entry({
			name: "@mod/a",
			dir: "modules/foundation/a",
			internal: [{ name: "inner", dir: "modules/foundation/a/src/inner", line: "Parses." }],
		}),
		entry({ name: "@mod/c", dir: "modules/oauth/c", line: undefined }),
	]);
	expect(listed).toContain(
		"## foundation\n\n- `@mod/a` (feature, `modules/foundation/a`): Does one thing.\n  - `inner` (`src/inner`): Parses.\n",
	);
	expect(listed).toContain("## oauth\n\n- `@mod/b` (feature, `modules/oauth/b`): Grants.\n");
	expect(listed).toContain("- `@mod/c` (feature, `modules/oauth/c`): its card names no line.\n");
	expect(listed).not.toContain("](");
	expect(listed.indexOf("## foundation")).toBeLessThan(listed.indexOf("## oauth"));
});

it("draws the directories each depends on, never itself, and lists each package's run-time dependencies", () => {
	const drawn = dependenciesOf([
		entry({ name: "@mod/k", dir: "modules/foundation/k", kind: "foundation" }),
		entry({
			name: "@mod/j",
			dir: "modules/foundation/j",
			kind: "foundation",
			dependsOn: ["@mod/k"],
		}),
		entry({ name: "@mod/g", dir: "modules/oauth/g", dependsOn: ["@mod/j", "@mod/k"] }),
	]);
	expect(drawn).toContain('  d0["foundation"]\n  d1["oauth"]\n  d1 --> d0\n');
	expect(drawn).not.toContain("d0 --> d0");
	expect(drawn).toContain("| `@mod/g` | feature | `@mod/j`, `@mod/k` |\n");
	expect(drawn).toContain("| `@mod/k` | foundation | none |\n");
});

it("reads every workspace package, run-time workspace dependencies alone", () => {
	const entries = auditIndexIn(root);
	const references = entries.find((e) => e.name === "@mod/references");
	expect(references?.dir).toBe("modules/tooling/references");
	expect(references?.dependsOn).toContain("@mod/guard-imports");
	expect(references?.dependsOn).not.toContain("vitest");
	expect(references?.internal.map((i) => i.name)).toContain("audit-index");
	expect(entries.some((e) => e.dir === "")).toBe(false);
});

it("holds, committed, the card list and the dependencies generated from the workspace as it is now", () => {
	const entries = auditIndexIn(root);
	expect(readFileSync(cardsFile(root), "utf8")).toBe(cardsOf(entries));
	expect(readFileSync(dependenciesFile(root), "utf8")).toBe(dependenciesOf(entries));
});
