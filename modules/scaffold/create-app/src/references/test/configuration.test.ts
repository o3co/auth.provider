import { readFileSync } from "node:fs";
import { expect, it, vi } from "vitest";
import { root } from "../../../test/full-app.ts";
import { referenceFile, referenceOf, rowsOf, sectionsIn } from "../configuration.ts";

// These tests read the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

it("describes each key by its schema: type and bounds, default, whether required, and the example's value and variable", () => {
	const schema = {
		type: "object",
		required: ["url", "mode"],
		properties: {
			url: { type: "string", description: "Where it sends." },
			mode: { enum: ["a", "b"], default: "a" },
			size: { type: "integer", minimum: 1, maximum: 10, default: 5 },
			hosts: { type: "array", items: { type: "string" } },
			retry: { type: "object", properties: { "max-ms": { type: "number" } } },
		},
	};
	const at = (key: string) =>
		key === "s.url" ? { env: "S_URL", example: "https://x.invalid" } : {};
	expect(rowsOf(schema, ["s"], at)).toEqual([
		{
			key: "s.url",
			type: "string",
			required: true,
			env: "S_URL",
			example: "https://x.invalid",
			description: "Where it sends.",
		},
		{ key: "s.mode", type: "a | b", default: "a", required: false },
		{ key: "s.size", type: "integer (1–10)", default: 5, required: false },
		{ key: "s.hosts", type: "list of string", required: false },
		{ key: "s.retry.max-ms", type: "number", required: false },
	]);
	expect(
		referenceOf([{ section: "s", owner: "@mod/s", rows: rowsOf(schema, ["s"], at) }]),
	).toContain("| `s.mode` | a \\| b | `a` |  |  |  |  |");
});

it("requires a key inside an object only when the object is required too", () => {
	const key = { type: "object", required: ["id"], properties: { id: { type: "string" } } };
	const schema = { type: "object", required: ["current"], properties: { current: key, next: key } };
	expect(rowsOf(schema, ["k"], () => ({}))).toEqual([
		{ key: "k.current.id", type: "string", required: true },
		{ key: "k.next.id", type: "string", required: false },
	]);
});

it("merges the keys of a union of objects, required only where every variant requires them", () => {
	const schema = {
		oneOf: [
			{ type: "object", required: ["mode"], properties: { mode: { const: "off" } } },
			{
				type: "object",
				required: ["mode", "hosts"],
				properties: { mode: { const: "on" }, hosts: { type: "array", items: { type: "string" } } },
			},
		],
	};
	expect(rowsOf(schema, ["u"], () => ({}))).toEqual([
		{ key: "u.mode", type: "off | on", required: true },
		{ key: "u.hosts", type: "list of string", required: false },
	]);
});

it("finds keys in every section, so none is left out by a shape the reference cannot read", async () => {
	const empty = (await sectionsIn(root)).filter((s) => s.rows.length === 0).map((s) => s.section);
	expect(empty).toEqual([]);
});

it("holds, committed, the reference generated from the workspace as it is now", async () => {
	expect(readFileSync(referenceFile(root), "utf8")).toBe(referenceOf(await sectionsIn(root)));
});

/** Sections whose keys are not all described yet; a section leaves once its owner describes it, and never comes back. */
const describedLater = new Set([
	"authorize",
	"clients",
	"clients-cimd",
	"federation-grants",
	"mfa-flows",
	"session",
]);

it("describes every key, but in the sections still listed as described later", async () => {
	const sections = await sectionsIn(root);
	const lacking = sections.flatMap(({ section, rows }) =>
		describedLater.has(section) ? [] : rows.filter((r) => !r.description).map((r) => r.key),
	);
	expect(lacking).toEqual([]);
	// A listed section that describes every key leaves the list.
	const done = sections.filter(
		(s) => describedLater.has(s.section) && s.rows.every((r) => r.description),
	);
	expect(done.map((s) => s.section)).toEqual([]);
});
