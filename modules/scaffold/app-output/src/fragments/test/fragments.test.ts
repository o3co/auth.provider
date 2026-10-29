import { readdirSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import {
	applicationConf,
	envExample,
	fragmentsIn,
	fragmentsOf,
	localConfExample,
	settingsOf,
	writtenOf,
} from "../contract.ts";

const fixtures = join(import.meta.dirname, "fixtures", "collide");

it("names each key's environment variable from the section and the key path, and refuses two keys reading one", async () => {
	const [one, other] = await fragmentsIn([join(fixtures, "one"), join(fixtures, "other")]);
	if (!one || !other) throw new Error("fixtures missing");
	expect(settingsOf([one]).map((s) => [s.key, s.env])).toEqual([
		["audit-http.url", "AUDIT_HTTP_URL"],
		["audit-http.retry.max-ms", "AUDIT_HTTP_RETRY_MAX_MS"],
	]);
	expect(() => settingsOf([one, other])).toThrow(
		"audit-http.url and audit.http-url both read AUDIT_HTTP_URL",
	);
});

it("skips a package without a fragment, and refuses one holding other than one section", async () => {
	expect(await fragmentsIn([join(fixtures, "none")])).toEqual([]);
	await expect(fragmentsIn([join(fixtures, "two")])).rejects.toThrow(
		"does not hold exactly one section",
	);
	await expect(fragmentsIn([join(fixtures, "one"), join(fixtures, "one")])).rejects.toThrow(
		"a second fragment for audit-http",
	);
});

it("keeps a value its owner's example gives in several lines out of the env example, read from env still and written in the local layer", () => {
	const text =
		'k {\n\tid = "REPLACE-KEY-ID"\n\tpem = """-----BEGIN KEY-----\nREPLACE-KEY\n-----END KEY-----"""\n}\n';
	const fragments = fragmentsOf([{ from: "k", text }]);
	expect(settingsOf(fragments).map((s) => s.env)).toEqual(["K_ID", "K_PEM"]);
	expect(envExample(settingsOf(fragments))).not.toContain("K_PEM");
	expect(envExample(settingsOf(fragments))).toContain("# K_ID=REPLACE-KEY-ID");
	expect(writtenOf(fragments)).toEqual([
		{
			key: "k.pem",
			example: '"""-----BEGIN KEY-----\nREPLACE-KEY\n-----END KEY-----"""',
			spansSections: false,
			severalLines: true,
		},
	]);
	expect(localConfExample(fragments)).toContain('# k.pem = """-----BEGIN KEY-----\n# REPLACE-KEY');
});

/** Each fragment the workspace's packages ship, by its package's directory. */
const shipped = () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..", "..");
	const groups = readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isDirectory());
	return groups.flatMap((group) =>
		readdirSync(join(root, group.name), { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.map((entry) => join(root, group.name, entry.name))
			.filter((dir) => readdirSync(dir).includes("config.example")),
	);
};

it("reads every fragment the workspace ships as before: none holds what a fragment is refused for", async () => {
	const dirs = shipped();
	expect(dirs.length).toBeGreaterThan(20);
	for (const dir of dirs) expect((await fragmentsIn([dir])).length, dir).toBe(1);
});

it("refuses a substitution, reading nothing from the environment", () => {
	process.env.FRAGMENT_CANARY = "canary-value";
	try {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: HOCON substitutions, not templates
		for (const value of ["${FRAGMENT_CANARY}", "${?FRAGMENT_CANARY}", '"a"${?FRAGMENT_CANARY}']) {
			const read = () => fragmentsOf([{ from: "s", text: `s { v = ${value} }` }]);
			expect(read).toThrow("s: a substitution, which a section example never holds");
			expect(read).not.toThrow(/canary-value/);
		}
	} finally {
		delete process.env.FRAGMENT_CANARY;
	}
});

it("refuses an include in each of its forms, reading no file", () => {
	for (const include of [
		'include "other.conf"',
		'include file("/etc/hosts")',
		'include required(file("other.conf"))',
		'include package("some-package", "x.conf")',
	]) {
		expect(() => fragmentsOf([{ from: "i", text: `${include}\ni { v = 1 }` }]), include).toThrow(
			"i: an include, which a section example never holds",
		);
	}
});

it("refuses a backtick or a control character in a key or a value: they reach the guide and the env example", () => {
	for (const text of [
		's { v = "a`b" }',
		's { "a`b" = 1 }',
		's { v = "a\u0007b" }',
		's { v = "a\rb" }',
		's { v = ["ok", "a`b"] }',
	]) {
		expect(() => fragmentsOf([{ from: "c", text }]), text).toThrow(
			"c: a backtick or a control character",
		);
	}
});

it("refuses a fragment over 64 KiB, and one whose keys and values come to over 32 KiB", () => {
	const big = `s { v = "${"x".repeat(64 * 1024)}" }`;
	expect(() => fragmentsOf([{ from: "b", text: big }])).toThrow("b: over 65536 bytes");
	const keys = Array.from({ length: 700 }, (_, i) => `k${i} = "${"x".repeat(40)}"`).join("\n");
	expect(() => fragmentsOf([{ from: "w", text: `s {\n${keys}\n}` }])).toThrow(
		"w: its keys and values come to over 32768 bytes",
	);
});

it("writes a quoted key with a dot in the local layer's example as that one key, so the copy reads back the fragment's own tree", () => {
	const text =
		's {\n\t"a.b" = ["REPLACE-A"]\n\tc {\n\t\t"d.e" = ["REPLACE-D"]\n\t}\n\tplain = ["REPLACE-P"]\n}\n';
	const fragments = fragmentsOf([{ from: "s", text }]);
	const copy = localConfExample(fragments)
		.split("\n")
		.filter((line) => !line.startsWith("## "))
		.map((line) => line.replace(/^# /, ""))
		.join("\n");
	expect(fragmentsOf([{ from: "copy", text: `${copy}\n` }])).toEqual(fragments);
	expect(writtenOf(fragments).map((w) => w.key)).toEqual(['s."a.b"', 's.c."d.e"', "s.plain"]);
});

it("writes a choice a shipped fragment gives, oidc's ID token algorithm, in no live line: a copy sets it only once the operator uncomments it", async () => {
	const fragments = await fragmentsIn(
		shipped().filter((dir) => dir.endsWith(join("oauth", "oidc"))),
	);
	expect(fragments).toHaveLength(1);
	const lines = (text: string) =>
		text.split("\n").filter((line) => line.includes("OIDC_ID_TOKEN_ALG"));
	expect(lines(envExample(settingsOf(fragments)))).toEqual(["# OIDC_ID_TOKEN_ALG=RS256"]);
	expect(localConfExample(fragments)).not.toMatch(/^[^#].*id-token-alg/m);
	// Read from env alone, so with no variable the file sets nothing.
	expect(lines(applicationConf(fragments))).toEqual([
		expect.stringMatching(/^\tid-token-alg = \$\{\?OIDC_ID_TOKEN_ALG\}$/),
	]);
});
