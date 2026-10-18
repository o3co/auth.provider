import { describe, expect, it, vi } from "vitest";
import { budget, pkg } from "../../../test/workspace.ts";
import { check } from "../../contract.ts";
import { pendingLimits } from "../pending.ts";

// A fixture with exports has its contract surface built by the type checker, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

describe("pending limits", () => {
	it("measures the limits still to come, refusing nothing: a card item's bytes and fixtures as test lines, never a widely used card's bytes", () => {
		const line = "export const n = 1;\n";
		const item = `- ${"x".repeat(30)}\n`;
		const wide = {
			...pkg("@t/wide", { "src/contract.ts": line }),
			// Past 5,000 bytes, within the card limit, in paragraphs that are no items.
			card: `# @t/wide\n${item.repeat(3)}${`${"p".repeat(999)}\n`.repeat(6)}`,
		};
		const users = [1, 2, 3, 4, 5].map((n) =>
			pkg(
				`@t/user${n}`,
				{ "src/contract.ts": line },
				{
					exports: { ".": "./src/contract.ts" },
					dependencies: { "@t/wide": "workspace:*" },
				},
			),
		);
		const tables = pkg("@t/fixtured", {
			"src/contract.ts": line,
			"src/inner/README.md": `# inner\n  - ${"y".repeat(40)}\n`,
			"src/inner/x.ts": line,
			"test/a.test.ts": line.repeat(2),
			"test/fixtures/big.ts": line.repeat(3),
			"test/cases.vectors.ts": line.repeat(10),
		});
		const tight = { ...budget, cardItemBytes: 40, testLines: 4 };
		const packages = [wide, ...users, tables];
		expect(check(packages, tight)).toEqual([]);
		expect(pendingLimits(packages, tight).map((v) => `${v.where} ${v.detail}`)).toEqual([
			"@t/fixtured test lines with fixtures 5 > 4",
			"@t/fixtured/src/inner card item bytes 44 > 40 (yyyyyyyyyyyy…)",
		]);
		expect(pendingLimits(packages, budget)).toEqual([]);
	});
});
