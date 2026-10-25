import { expect, it, vi } from "vitest";
import { pkg } from "../../../test/workspace.ts";
import { surfacesOf } from "../../contract.ts";

// Each case builds a TypeScript program over its package, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

/** The surface of a package whose entry is `contract`, its other files beside it. */
const surface = (name: string, contract: string, files: Record<string, string> = {}) => {
	const p = pkg(name, { "src/contract.ts": contract, ...files });
	const read = surfacesOf([p]).get(name);
	if (!read) throw new Error(`no surface for ${name}`);
	return read;
};

const base = `
export interface Store { get(key: string): Promise<string | undefined>; readonly size: number }
export const limit = 3;
export function find(id: string, strict?: boolean): number { return strict ? 1 : 0; }
export type Mode = "a" | "b";
export enum Level { Low = 1, High = 2 }
`;

it("gives each export a signature of its structure: members with their optionality and types, calls, and values", () => {
	const { signatures } = surface("@mod/sig-base", base);
	expect([...signatures.keys()].sort()).toEqual(["Level", "Mode", "Store", "find", "limit"]);
	expect(signatures.get("Store")).toBe(
		[
			"type Store",
			"  get: (key: string) => Promise<string | undefined>",
			"  readonly size: number",
		].join("\n"),
	);
	expect(signatures.get("find")).toBe(
		"value find: (id: string, strict?: boolean | undefined) => number",
	);
	expect(signatures.get("Mode")).toBe('type Mode = "a" | "b"');
	expect(signatures.get("Level")).toBe(["enum Level", "  High = 2", "  Low = 1"].join("\n"));
});

it("tells a change the member count keeps: a parameter's type, and one member put in another's place", () => {
	const before = surface("@mod/sig-before", base);
	const typed = surface("@mod/sig-typed", base.replace("get(key: string)", "get(key: number)"));
	const swapped = surface(
		"@mod/sig-swapped",
		base.replace("readonly size: number", "readonly count: number"),
	);
	expect([typed.members, swapped.members]).toEqual([before.members, before.members]);
	expect(typed.signatures.get("Store")).not.toBe(before.signatures.get("Store"));
	expect(swapped.signatures.get("Store")).not.toBe(before.signatures.get("Store"));
	const optional = surface(
		"@mod/sig-optional",
		base.replace("strict?: boolean", "strict: boolean"),
	);
	expect(optional.signatures.get("find")).not.toBe(before.signatures.get("find"));
	const member = surface(
		"@mod/sig-member",
		base.replace("readonly size: number", "readonly size?: number"),
	);
	expect(member.signatures.get("Store")).toContain("readonly size?: number");
	const generic = (bound: string) =>
		surface(
			`@mod/sig-generic-${bound}`,
			`export interface Box<T extends ${bound}> { take(item: T): void }\n`,
		).signatures.get("Box");
	expect(generic("string")).not.toBe(generic("number"));
});

it("keeps a signature where its declaration moves to another file of the package, and drops or renames it with its export", () => {
	const before = surface("@mod/sig-stay", base);
	const moved = surface(
		"@mod/sig-moved",
		`export type { Store } from "./store.ts";\n${base.replace(/export interface Store[^\n]*\n/, "")}`,
		{
			"src/store.ts":
				"export interface Store { get(key: string): Promise<string | undefined>; readonly size: number }\n",
		},
	);
	expect(moved.signatures.get("Store")).toBe(before.signatures.get("Store"));
	const dropped = surface(
		"@mod/sig-dropped",
		base.replace("export const limit = 3;", "const limit = 3;"),
	);
	expect(dropped.signatures.has("limit")).toBe(false);
	const renamed = surface(
		"@mod/sig-renamed",
		base.replace("export const limit", "export const most"),
	);
	expect([renamed.signatures.has("limit"), renamed.signatures.get("most")]).toEqual([
		false,
		"value most: 3",
	]);
});
