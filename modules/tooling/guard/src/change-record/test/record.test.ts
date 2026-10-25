import { expect, it, vi } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { changeRecordOf, changesOf, type Reading, readingOf } from "../record.ts";

// The fixtures' surfaces are built by the type checker, slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const reading = (over: Partial<Reading>): Reading => ({
	commit: "c0",
	tree: "t0",
	files: new Map(),
	signatures: new Map(),
	edges: new Set(),
	measures: new Map(),
	...over,
});

it("tells the units added, removed, moved and changed", () => {
	const base = reading({
		files: new Map([
			["@t/a", new Map([["src/contract.ts", "h1"]])],
			["@t/a/src/old", new Map([["src/old/old.ts", "h2"]])],
			["@t/a/src/inner", new Map([["src/inner/inner.ts", "h3"]])],
			["@t/gone", new Map([["src/contract.ts", "h4"]])],
		]),
	});
	const head = reading({
		files: new Map([
			["@t/a", new Map([["src/contract.ts", "h1-changed"]])],
			["@t/a/src/parts/inner", new Map([["src/parts/inner/inner.ts", "h3"]])],
			["@t/a/src/old", new Map([["src/old/old.ts", "h2"]])],
			["@t/new", new Map([["src/contract.ts", "h5"]])],
		]),
	});
	expect(changesOf(base, head).units).toEqual({
		added: ["@t/new"],
		removed: ["@t/gone"],
		moved: [["@t/a/src/inner", "@t/a/src/parts/inner"]],
		changed: ["@t/a"],
	});
});

it("tells a move only where the last part matches one gone unit and one come, else the removals and the addition", () => {
	const files = (...wheres: string[]) =>
		new Map(wheres.map((w) => [w, new Map([["src/x.ts", w]])]));
	const units = changesOf(
		reading({ files: files("@t/a/src/util", "@t/b/src/util", "@t/c/src/one") }),
		reading({ files: files("@t/c/src/util", "@t/c/src/parts/one") }),
	).units;
	expect(units).toEqual({
		added: ["@t/c/src/util"],
		removed: ["@t/a/src/util", "@t/b/src/util"],
		moved: [["@t/c/src/one", "@t/c/src/parts/one"]],
		changed: [],
	});
});

it("tells each export added, removed, renamed, moved or changed, a swap of members of the same count too", () => {
	const base = reading({
		signatures: new Map([
			[
				"@t/a",
				new Map([
					["swap", "{ a: string }"],
					["call", "(n: number) => void"],
					["gone", "1"],
					["old", "{ o: boolean }"],
					["mover", "{ m: 1 }"],
				]),
			],
			["@t/b", new Map()],
		]),
	});
	const head = reading({
		signatures: new Map([
			[
				"@t/a",
				new Map([
					["swap", "{ b: string }"],
					["call", "(n: string) => void"],
					["fresh", "{ o: boolean }"],
					["added", "2"],
				]),
			],
			["@t/b", new Map([["mover", "{ m: 1 }"]])],
		]),
	});
	expect(changesOf(base, head).contract).toEqual([
		{ package: "@t/a", name: "added", kind: "added" },
		{
			package: "@t/a",
			name: "call",
			kind: "changed",
			from: "(n: number) => void",
			to: "(n: string) => void",
		},
		{ package: "@t/a", name: "gone", kind: "removed" },
		{ package: "@t/a", name: "mover", kind: "moved", to: "@t/b" },
		{ package: "@t/a", name: "old", kind: "renamed", to: "fresh" },
		{ package: "@t/a", name: "swap", kind: "changed", from: "{ a: string }", to: "{ b: string }" },
	]);
});

it("tells the dependency edges added and removed, and each budget measure that moved", () => {
	const base = reading({
		edges: new Set(["@t/a -> @t/k (run time)", "@t/a -> @t/old (tests)"]),
		measures: new Map([
			["@t/a\tsource lines", { value: 10, limit: 1500 }],
			["@t/a\tcard bytes", { value: 900, limit: 6500 }],
			["@t/a\tcard items", { value: 4 }],
		]),
	});
	const head = reading({
		edges: new Set(["@t/a -> @t/k (run time)", "@t/a -> @t/new (run time)"]),
		measures: new Map([
			["@t/a\tsource lines", { value: 12, limit: 1500 }],
			["@t/a\tcard bytes", { value: 850, limit: 6500 }],
			["@t/a\tcard items", { value: 4 }],
			["@t/a/src/inner\ttest lines", { value: 30, limit: 2000 }],
		]),
	});
	const { edges, measures } = changesOf(base, head);
	expect(edges).toEqual({
		added: ["@t/a -> @t/new (run time)"],
		removed: ["@t/a -> @t/old (tests)"],
	});
	expect(measures).toEqual([
		{ where: "@t/a", what: "card bytes", from: 900, to: 850, limit: 6500 },
		{ where: "@t/a", what: "source lines", from: 10, to: 12, limit: 1500 },
		{ where: "@t/a/src/inner", what: "test lines", to: 30, limit: 2000 },
	]);
});

it("writes the record's machine rows, and names the ones left to hand", () => {
	const base = reading({ commit: "aaa", tree: "ta" });
	const head = reading({
		commit: "bbb",
		tree: "tb",
		edges: new Set(["@t/a -> @t/new (run time)"]),
		measures: new Map([["@t/a\tsource lines", { value: 3, limit: 1500 }]]),
	});
	const record = changeRecordOf(base, head);
	expect(record).toContain("| base | `aaa` | `ta` |\n| head | `bbb` | `tb` |\n");
	expect(record).toContain("## Dependency edges\n\n- Added: `@t/a -> @t/new (run time)`\n");
	expect(record).toContain("| `@t/a` | source lines |  | 3 | 1500 |\n");
	expect(record).toContain("compared by their structure.\n\nNone.\n");
	expect(record).toMatch(/By hand: .*owner.*review/);
});

it("reads a workspace's state: each unit's files, the signatures, the edges and the measures", () => {
	const make = (members: string) =>
		pkg(
			`@t/read-${members}`,
			{
				"src/contract.ts": `export interface Shape { ${members}: string }\n`,
				"src/inner/README.md": "# inner\n",
				"src/inner/a.ts": "export const n = 1;\n",
			},
			{ exports: { ".": "./src/contract.ts" }, dependencies: { "@t/k": "workspace:*" } },
		);
	const k = pkg("@t/k", { "src/contract.ts": "export const k = 1;\n" });
	const one = readingOf([make("left"), k], budget, { commit: "c1", tree: "t1" });
	const other = readingOf([make("right"), k], budget, { commit: "c2", tree: "t2" });
	expect([...(one.files.get("@t/read-left/src/inner")?.keys() ?? [])]).toEqual([
		"src/inner/README.md",
		"src/inner/a.ts",
	]);
	expect(one.edges).toEqual(new Set(["@t/read-left -> @t/k (run time)"]));
	expect(one.measures.get("@t/read-left\tcontract members")).toEqual({
		value: 1,
		limit: budget.contractMembers,
	});
	// A member swapped for another keeps the count, but not the signature.
	expect(one.signatures.get("@t/read-left")?.get("Shape")).not.toBe(
		other.signatures.get("@t/read-right")?.get("Shape"),
	);
});
