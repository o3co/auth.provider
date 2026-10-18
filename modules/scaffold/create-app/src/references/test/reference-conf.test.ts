import { readFileSync } from "node:fs";
import { setting } from "@mod/kernel";
import { parseString } from "@o3co/ts.hocon";
import { expect, it, vi } from "vitest";
import { root } from "../../../test/full-app.ts";
import { referenceConfFile, referenceConfOf, type Section, sectionsIn } from "../configuration.ts";
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
const nodes = (s: Section) => nodesOf(s.schema as unknown as Node, [s.section]);

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
		const stale = `${s.owner}'s reference.conf is generated from its schema: run \`pnpm --filter @mod/create-app run configuration\``;
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
	for (const s of await sections) {
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

/** Sections whose time and size keys still name their unit or take a bare number; a section leaves once its owner moves it, and never comes back. */
const unitsLater = new Set([
	"code-grant",
	"federation-grants",
	"mail-smtp",
	"mfa",
	"mfa-email",
	"mfa-flows",
	"mtls",
	"outbound",
	"passkey-registration",
	"redis",
	"refresh",
	"rp-logout",
	"session-lifecycle",
	"token-endpoint",
	"token-exchange",
	"tokens",
	"users-http",
	"webauthn",
	"webauthn-login",
]);
/** Sections whose schema still gives a default by `.default()`; a section leaves once its owner moves it, and never comes back. */
const prefaultLater = new Set([
	"code-grant-store",
	"federation-grants",
	"federation-grants-store",
	"mail-smtp",
	"mfa",
	"mfa-email",
	"mfa-flows",
	"mfa-webauthn",
	"mtls",
	"outbound",
	"passkey-registration",
	"rate-limit",
	"redis",
	"refresh",
	"refresh-store",
	"rp-logout",
	"rp-logout-store",
	"secret-hash",
	"sender-binding",
	"session-lifecycle",
	"session-store",
	"session-tokens-store",
	"store",
	"token-endpoint",
	"webauthn-login",
]);

/** Each place a rule is broken: the key path, in its section. */
async function broken(breaks: (placed: Placed) => Promise<boolean>) {
	const found: { section: string; key: string }[] = [];
	for (const s of await sections) {
		for (const placed of nodes(s)) {
			if (await breaks(placed)) found.push({ section: s.section, key: placed.path.join(".") });
		}
	}
	return found;
}

/** The places that break `rule` outside the sections listed for later, and each listed section that no longer does. */
function outsideLater(found: { section: string; key: string }[], later: Set<string>, rule: string) {
	const left = [...later].filter((s) => !found.some((f) => f.section === s));
	return [
		...found.filter((f) => !later.has(f.section)).map((f) => `${f.key}: ${rule}`),
		...left.map((s) => `${s}: keeps the rule now, so leaves the list for later`),
	];
}

const unitRule =
	"a time or a size is read by kernel's setting.duration or setting.size, under a name that carries no unit";
const prefaultRule =
	"a default is given by .prefault(value), written as an operator writes it, never by .default()";

it("reads time and size by a marker asked for its unit, under a name without one, but in the sections still listed", async () => {
	const found = await broken(
		async ({ node, path, key }) =>
			key &&
			(/-(seconds|ms|bytes)$/.test(path.at(-1) ?? "") ||
				((await readsUnits(node)) && !(await refusesUnitless(node)))),
	);
	expect(outsideLater(found, unitsLater, unitRule)).toEqual([]);
});

it("gives each default by `.prefault`, read as an operator's value is, but in the sections still listed", async () => {
	const found = await broken(async ({ node }) => node._zod.def.type === "default");
	expect(outsideLater(found, prefaultLater, prefaultRule)).toEqual([]);
});
