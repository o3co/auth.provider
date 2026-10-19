import { readFileSync } from "node:fs";
import { expect, it, vi } from "vitest";
import { root } from "../../../test/full-app.ts";
import {
	clientSectionsOf,
	idpTypesOf,
	referenceFile,
	referenceOf,
	rowsOf,
	sectionsIn,
} from "../configuration.ts";

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

it("writes a client metadata section under `sections`, by the module that adds it, after the sections", () => {
	const schema = { type: "object", properties: { hosts: { type: "array", default: [] } } };
	const rows = rowsOf(schema, ["sections", "c"], () => ({}));
	const reference = referenceOf([], [{ section: "c", owner: "@mod/c", rows }]);
	expect(reference).toContain("## Client metadata sections");
	expect(reference).toContain("### sections.c\n\nFrom `@mod/c`.");
	expect(reference).toContain("| `sections.c.hosts` | list of any | `[]` |  |  |");
});

it("finds the client metadata sections that full with every opt-in composes, each by its contributor", async () => {
	const found = await clientSectionsOf(root);
	expect(found.find((s) => s.section === "client-secret")?.owner).toBe("@mod/clients");
	expect(found.filter((s) => s.rows.length === 0).map((s) => s.section)).toEqual([]);
});

it("finds each IdP type's settings that full with every opt-in composes, by the module that adds the type", async () => {
	const types = await idpTypesOf(root);
	expect(types.map((t) => [t.section, t.owner])).toEqual([
		["apple", "@mod/idp-apple"],
		["github", "@mod/idp-github"],
		["google", "@mod/idp-google"],
		["oidc", "@mod/idp-oidc"],
	]);
	expect(types.find((t) => t.section === "oidc")?.rows.map((r) => r.key)).toContain(
		"federation.idps.<name>.algorithms",
	);
});

it("holds, committed, the reference generated from the workspace as it is now", async () => {
	const reference = referenceOf(
		await sectionsIn(root),
		await clientSectionsOf(root),
		await idpTypesOf(root),
	);
	expect(readFileSync(referenceFile(root), "utf8")).toBe(reference);
});

it("describes every key of every section", async () => {
	const lacking = (await sectionsIn(root)).flatMap(({ rows }) =>
		rows.filter((r) => !r.description).map((r) => r.key),
	);
	expect(lacking).toEqual([]);
});

/** Client metadata sections whose keys their owners describe later: one leaves once described, and the list only shrinks. */
const clientsDescribedLater = [
	"authorize",
	"client-allowance",
	"client-secret",
	"federation-grants",
	"federation-tokens",
];

it("describes every key of every client metadata section, outside those listed as described later", async () => {
	const clients = await clientSectionsOf(root);
	const lacking = clients
		.filter((s) => !clientsDescribedLater.includes(s.section))
		.flatMap(({ rows }) => rows.filter((r) => !r.description).map((r) => r.key));
	expect(lacking).toEqual([]);
	const described = clients
		.filter((s) => clientsDescribedLater.includes(s.section) && s.rows.every((r) => r.description))
		.map((s) => `${s.section}: describes every key, so it leaves the list`);
	expect(described).toEqual([]);
});

/** IdP types whose settings their owners describe later: one leaves once described, and the list only shrinks. */
const typesDescribedLater = ["apple", "github", "google", "oidc"];

it("describes every key of every IdP type's settings, outside the types listed as described later", async () => {
	const types = await idpTypesOf(root);
	const lacking = types
		.filter((t) => !typesDescribedLater.includes(t.section))
		.flatMap(({ rows }) => rows.filter((r) => !r.description).map((r) => r.key));
	expect(lacking).toEqual([]);
	const described = types
		.filter((t) => typesDescribedLater.includes(t.section) && t.rows.every((r) => r.description))
		.map((t) => `${t.section}: describes every key, so it leaves the list`);
	expect(described).toEqual([]);
});
