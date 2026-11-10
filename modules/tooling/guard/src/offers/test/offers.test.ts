import { expect, it, vi } from "vitest";
import { pkg } from "../../../test/workspace.ts";
import { listedOn, unlistedExports } from "../offers.ts";

// Each package's entry points are read by a TypeScript program, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const card = (offers: string, deprecated = "") =>
	`# x\n\n## Responsibilities\n- \`aside\` is not offered here.\n\n## Offers\n${offers}\n${deprecated ? `\n## Deprecated\n${deprecated}\n` : ""}\n## Invariants\n- \`later\` neither.\n`;

it("lists the names its Offers and Deprecated sections backtick, or a call, type, member or index opens with", () => {
	const listed = listedOn(
		card(
			"- `made(options)`: one; `Store<T>`, `points.read` and `rows[0]`.\n- `pnpm run thing` and plain words: none.",
			"- `old`: use `made`.",
		),
	);
	expect([...listed].sort()).toEqual(["Store", "made", "old", "points", "rows"]);
});

const contract = `
declare function contract<T>(name: string): { readonly name: string; readonly of?: T };
export interface Part { readonly size: number }
export interface Whole { readonly part: Part }
export interface Store { get(key: string): Promise<Whole | undefined> }
export interface Alone { readonly id: string }
export const store = contract<Store>("store");
export function made(): Whole { return { part: { size: 1 } }; }
export const limit = 3;
export const old = 2;
`;

it("asks every value, and the types no value carries, at each entry; a module's default and carried types aside", () => {
	const p = {
		...pkg(
			"@mod/offers-listed",
			{
				"src/contract.ts": contract,
				"src/testing.ts":
					"export interface Fake { readonly id: string }\nexport const fake = (): Fake => ({ id: '' });\n",
				"src/module.ts": "export default { name: 'x' };\nexport const section = 1;\n",
			},
			{
				exports: {
					".": "./src/contract.ts",
					"./testing": "./src/testing.ts",
					"./module": "./src/module.ts",
				},
			},
		),
		card: card(
			"- `store` and `made()`.\n- `./testing`: `fake`.",
			"- `old`: a later release removes it.",
		),
	};
	expect(unlistedExports([p])).toEqual([
		{ where: "@mod/offers-listed", entry: ".", names: ["limit", "Alone"] },
		{ where: "@mod/offers-listed", entry: "./module", names: ["section"] },
	]);
});

it("asks a default exported from any entry but `./module`", () => {
	const p = {
		...pkg("@mod/offers-default", {
			"src/contract.ts": "export default function made(): void {}\n",
		}),
		card: card("- Nothing named."),
	};
	expect(unlistedExports([p])).toEqual([
		{ where: "@mod/offers-default", entry: ".", names: ["default"] },
	]);
});
