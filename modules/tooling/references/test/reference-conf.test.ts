import { readFileSync } from "node:fs";
import { setting } from "@mod/kernel";
import { parseString } from "@o3co/ts.hocon";
import { expect, it, vi } from "vitest";
import {
	type ClientSection,
	clientSectionsOf,
	idpTypesOf,
	referenceConfFile,
	referenceConfOf,
	sectionsIn,
} from "../src/configuration.ts";
import { root } from "./root.ts";
import {
	accepts,
	type Node,
	nodesOf,
	type Placed,
	readsUnits,
	refusesUnitless,
} from "./schema-nodes.ts";

// These tests read the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

const sections = sectionsIn(root);
/** Each section held to the rules: the operator's, those modules add to client records, and the IdP types' settings. */
const checked = Promise.all([sections, clientSectionsOf(root), idpTypesOf(root)]).then(
	([own, clients, types]) => [...own, ...clients, ...types],
);
const nodes = (s: ClientSection) => nodesOf(s.schema as unknown as Node, [s.section]);

it("writes a section's defaults as HOCON: each described, a unit value bare, a key without a default as a comment", () => {
	const rows = [
		{ key: "s.ttl", type: "integer", default: "5m", required: false, description: "How long." },
		{ key: "s.retry.hosts", type: "list of string", default: ["a"], required: false },
		{ key: "s.url", type: "string", required: true },
		{ key: "s.proxy", type: "string", required: false },
	];
	const conf = referenceConfOf({ section: "s", owner: "@mod/s", rows });
	expect(conf.split("\n").slice(2)).toEqual([
		"s {",
		"\t# How long.",
		"\tttl = 5m",
		'\tretry.hosts = ["a"]',
		"\t# url: required",
		"\t# proxy: optional",
		"}",
		"",
	]);
	expect(parseString(conf).get("s")).toEqual({ ttl: "5m", retry: { hosts: ["a"] } });
});

it("holds, committed beside each package, the defaults generated from its section's schema", async () => {
	for (const s of await sections) {
		const conf = readFileSync(referenceConfFile(s.dir), "utf8");
		const stale = `${s.owner}'s reference.conf is generated from its schema: run \`pnpm --filter @mod/references run configuration\``;
		expect(conf, stale).toBe(referenceConfOf(s));
		for (const r of s.rows.filter((r) => r.default !== undefined)) {
			expect(parseString(conf).get(r.key), r.key).toEqual(r.default);
		}
	}
});

const prefaultReads =
	"a prefault is written as an operator writes the key, so the key's own schema reads it";

it("reads every section's prefault through the schema of its key", async () => {
	const unread = [];
	for (const s of await checked) {
		for (const { node, path } of nodes(s)) {
			const { type, innerType, defaultValue } = node._zod.def;
			if (type === "prefault" && innerType && !(await accepts(innerType, defaultValue))) {
				unread.push(`${path.join(".")}: ${prefaultReads}`);
			}
		}
	}
	expect(unread).toEqual([]);
});

/** A key that reads time with its unit, but takes a bare number too, in the default unit. */
const unitOptional: Node = {
	_zod: { def: { type: "pipe" } },
	"~standard": { validate: (value) => ({ value: value === "1s" ? 1 : 0.001 }) },
};

it("tells a key that reads time or size with its unit asked for from one that takes a bare number", async () => {
	const duration = setting.duration("s") as unknown as Node;
	expect(await readsUnits(duration)).toBe(true);
	expect(await refusesUnitless(duration)).toBe(true);
	expect(await readsUnits(setting.size() as unknown as Node)).toBe(true);
	expect(await readsUnits(unitOptional)).toBe(true);
	expect(await refusesUnitless(unitOptional)).toBe(false);
});

/** Each place that breaks `rule`, by its key path. */
async function breaking(rule: string, breaks: (placed: Placed) => Promise<boolean>) {
	const found: string[] = [];
	for (const s of await checked) {
		for (const placed of nodes(s)) {
			if (await breaks(placed)) found.push(`${placed.path.join(".")}: ${rule}`);
		}
	}
	return found;
}

const unitRule =
	"a time or a size is read by kernel's setting.duration or setting.size, under a name that carries no unit";
const prefaultRule =
	"a default is given by .prefault(value), written as an operator writes it, never by .default()";

it("reads time and size in every section by a marker asked for its unit, under a name without one", async () => {
	const found = await breaking(
		unitRule,
		async ({ node, path, key }) =>
			key &&
			(/-(seconds|ms|bytes)$/.test(path.at(-1) ?? "") ||
				((await readsUnits(node)) && !(await refusesUnitless(node)))),
	);
	expect(found).toEqual([]);
});

it("gives each default in every section by `.prefault`, read as an operator's value is", async () => {
	const found = await breaking(prefaultRule, async ({ node }) => node._zod.def.type === "default");
	expect(found).toEqual([]);
});
