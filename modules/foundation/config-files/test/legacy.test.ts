import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BootRefused } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	legacyVariablesCheck,
	legacyVariablesWarning,
	unreadLegacyVariables,
} from "../src/contract.ts";

async function files(...contents: string[]): Promise<string[]> {
	const dir = await mkdtemp(join(tmpdir(), "config-files-"));
	return Promise.all(
		contents.map(async (content, i) => {
			const path = join(dir, `${i}.conf`);
			await writeFile(path, content);
			return path;
		}),
	);
}

describe("unreadLegacyVariables", () => {
	it("names each set 0.17 variable no file reads, in order, and never a value", async () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const paths = await files("a = ${?KEPT}");
		const names = await unreadLegacyVariables({
			files: paths,
			env: {
				OAUTH_ACCESS_TOKEN_EXPIRES_IN: "60",
				CORE_DEPLOYMENT_MODE: "multi-secret",
				KEPT: "1",
				NOT_FROM_017: "x",
			},
		});
		expect(names).toEqual(["CORE_DEPLOYMENT_MODE", "OAUTH_ACCESS_TOKEN_EXPIRES_IN"]);
		expect(JSON.stringify(names)).not.toMatch(/60|multi-secret/);
	});

	it("leaves out a 0.17 name a file reads, in any layer, and one with no value", async () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const paths = await files("a = 1", "log { level = ${?LOG_LEVEL} }");
		const env = { LOG_LEVEL: "debug", REDIS_CLIENTS_URL: undefined };
		expect(await unreadLegacyVariables({ files: paths, env })).toEqual([]);
	});

	it("names nothing without a 0.17 variable set", async () => {
		const paths = await files("a = 1");
		expect(await unreadLegacyVariables({ files: paths, env: { PATH: "/bin" } })).toEqual([]);
	});
});

describe("legacyVariablesWarning", () => {
	it("tells how many and which, pointing at the migration guide", () => {
		expect(legacyVariablesWarning(["A_ONE", "B_TWO"])).toBe(
			"2 variables named in 0.17 are set and never read: A_ONE, B_TWO; see docs/migration.md",
		);
		expect(legacyVariablesWarning(["A_ONE"])).toBe(
			"1 variable named in 0.17 is set and never read: A_ONE; see docs/migration.md",
		);
	});

	it("tells nothing for none", () => {
		expect(legacyVariablesWarning([])).toBeUndefined();
	});
});

describe("legacyVariablesCheck", () => {
	const set = { OAUTH_ACCESS_TOKEN_EXPIRES_IN: "60", CORE_DEPLOYMENT_MODE: "multi-secret" };
	const refusalsOf = (error: unknown) =>
		BootRefused.is(error) ? error.refusals.map((r) => `${r.where}: ${r.reason}`) : [];

	it("warns by default, and under warn, naming each and never a value", async () => {
		const paths = await files("a = 1");
		const warning =
			"2 variables named in 0.17 are set and never read: CORE_DEPLOYMENT_MODE, OAUTH_ACCESS_TOKEN_EXPIRES_IN; see docs/migration.md";
		expect(await legacyVariablesCheck({ files: paths, env: set })).toBe(warning);
		expect(
			await legacyVariablesCheck({ files: paths, env: { ...set, APP_LEGACY_VARIABLES: "warn" } }),
		).toBe(warning);
		expect(await legacyVariablesCheck({ files: paths, env: { PATH: "/bin" } })).toBeUndefined();
	});

	it("refuses boot under refuse, naming each and never a value, and passes with none set", async () => {
		const paths = await files("a = 1");
		const env = { ...set, APP_LEGACY_VARIABLES: "refuse" };
		const refused = await legacyVariablesCheck({ files: paths, env }).then(() => [], refusalsOf);
		expect(refused).toEqual([
			"config-files: 2 variables named in 0.17 are set and never read: CORE_DEPLOYMENT_MODE, OAUTH_ACCESS_TOKEN_EXPIRES_IN; remove them, or set APP_LEGACY_VARIABLES to warn or ignore; see docs/migration.md",
		]);
		expect(JSON.stringify(refused)).not.toMatch(/60|multi-secret/);
		const none = { PATH: "/bin", APP_LEGACY_VARIABLES: "refuse" };
		expect(await legacyVariablesCheck({ files: paths, env: none })).toBeUndefined();
	});

	it("checks nothing under ignore", async () => {
		const paths = await files("a = 1");
		const env = { ...set, APP_LEGACY_VARIABLES: "ignore" };
		expect(await legacyVariablesCheck({ files: paths, env })).toBeUndefined();
	});

	it("refuses boot at APP_LEGACY_VARIABLES for any other value, never showing it", async () => {
		const paths = await files("a = 1");
		for (const value of ["", "Warn", "off", "refuse "]) {
			const env = { ...set, APP_LEGACY_VARIABLES: value };
			const refused = await legacyVariablesCheck({ files: paths, env }).then(() => [], refusalsOf);
			expect(refused, value).toEqual(["APP_LEGACY_VARIABLES: one of warn, refuse or ignore"]);
		}
	});
});
