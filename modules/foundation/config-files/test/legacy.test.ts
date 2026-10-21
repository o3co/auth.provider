import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { legacyVariablesWarning, unreadLegacyVariables } from "../src/contract.ts";

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
