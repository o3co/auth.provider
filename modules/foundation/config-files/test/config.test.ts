import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assemble, contract, defineModule } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { loadConfig } from "../src/contract.ts";
import { refusalsOf } from "./refusals.ts";

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

afterEach(() => {
	vi.unstubAllEnvs();
});

describe("loadConfig", () => {
	it("layers files with the first one winning and resolves env only from the given env", async () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const paths = await files("a { x = 1 }", "a { x = 2, y = ${?Y} }\nb = 3");
		const config = await loadConfig({ files: paths, env: { Y: "from-env" } });
		expect(config).toEqual({ a: { x: 1, y: "from-env" }, b: 3 });
	});

	it("layers three files with the earlier one winning at each key", async () => {
		const paths = await files("a = 1", "a = 2\nb = 2", "a = 3\nb = 3\nc = 3");
		expect(await loadConfig({ files: paths, env: {} })).toEqual({ a: 1, b: 2, c: 3 });
	});

	it("resolves a substitution within its own file only", async () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const paths = await files("a = ${b}", "b = 1");
		const refusals = await refusalsOf(loadConfig({ files: paths, env: {} }));
		expect(refusals.map((r) => r.where.startsWith(`${paths[0]}:1:`))).toEqual([true]);
		expect(refusals.map((r) => r.reason)).toEqual(["cannot resolve b"]);
	});

	it("reads no environment but the one it is given", async () => {
		vi.stubEnv("KERNEL_TEST_UNGIVEN", "leak");
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const paths = await files("a = ${?KERNEL_TEST_UNGIVEN}");
		expect(await loadConfig({ files: paths, env: {} })).toEqual({});
	});

	it("resolves only the environment's own variables, never what every object inherits", async () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const paths = await files("a = 1\na = ${?constructor}\nb = ${?toString}");
		expect(await loadConfig({ files: paths, env: {} })).toEqual({ a: 1 });
	});

	it("reads no file as an empty tree", async () => {
		expect(await loadConfig({ files: [], env: {} })).toEqual({});
	});

	it("takes an environment variable left undefined as one not set", async () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const paths = await files("a = 1\na = ${?A}");
		expect(await loadConfig({ files: paths, env: { A: undefined } })).toEqual({ a: 1 });
	});

	it("keeps objects inside arrays across layers", async () => {
		const paths = await files("a = [{ x = 1 }, { x = 2 }]", "b = [{ y = 3 }]");
		expect(await loadConfig({ files: paths, env: {} })).toEqual({
			a: [{ x: 1 }, { x: 2 }],
			b: [{ y: 3 }],
		});
	});

	it("does not mix the environment into the tree", async () => {
		const config = await loadConfig({ files: await files("a = 1"), env: { HOME: "/x" } });
		expect(config).toEqual({ a: 1 });
	});

	it("refuses unreadable and malformed files without quoting them", async () => {
		const unreadable = await refusalsOf(loadConfig({ files: ["/nonexistent.conf"], env: {} }));
		expect(unreadable.map((r) => r.where)).toEqual(["/nonexistent.conf"]);
		const [file] = await files("a = 1\nb = { secret-value");
		const located = await refusalsOf(loadConfig({ files: [file as string], env: {} }));
		expect(located).toEqual([
			{ where: expect.stringMatching(/:2:\d+$/), reason: "not readable as HOCON" },
		]);
		expect(located[0]?.where.startsWith(`${file}:`)).toBe(true);
		expect(JSON.stringify(located)).not.toContain("secret-value");
		// biome-ignore lint/suspicious/noTemplateCurlyInString: a HOCON substitution, not a template
		const substituting = "a = 1\nb = ${missing}";
		const unresolved = await refusalsOf(loadConfig({ files: await files(substituting), env: {} }));
		expect(unresolved.map((r) => r.reason)).toEqual(["cannot resolve missing"]);
	});
});

describe("sections read from loaded files", () => {
	const seen = contract<unknown>("seen");
	const server = defineModule(
		{ name: "server", section: z.strictObject({ port: z.number(), tls: z.boolean() }), takes: [] },
		(m) => [m.provide(seen).by((c) => c.section)],
	);
	async function boot(env: Record<string, string>) {
		const paths = await files(
			// biome-ignore lint/suspicious/noTemplateCurlyInString: HOCON substitutions, not a template
			"kernel.deployment = single\nserver { port = ${?PORT}, tls = ${?TLS} }",
		);
		const config = await loadConfig({ files: paths, env });
		return assemble({ modules: [server], config, runtime: quietRuntime() });
	}

	it("converts environment strings to the numbers and booleans a section asks for", async () => {
		const app = await boot({ PORT: "8081", TLS: "true" });
		expect(app.get(seen)).toEqual({ port: 8081, tls: true });
	});

	it("refuses a number written in hex, empty or padded, without quoting it", async () => {
		for (const port of ["0x50", "", " 80"]) {
			const refusals = await refusalsOf(boot({ PORT: port, TLS: "on" }));
			expect(
				refusals.map((r) => r.where),
				JSON.stringify(port),
			).toEqual(["server.port"]);
			if (port.trim() !== "") expect(JSON.stringify(refusals)).not.toContain(port.trim());
		}
	});

	it("refuses a key that names an object's prototype in a file, by its path and never its value", async () => {
		const limits = defineModule({
			name: "m",
			section: z.strictObject({ limits: z.record(z.string(), z.number()) }),
			takes: [],
		});
		const paths = await files(
			'kernel.deployment = single\nm { limits { "__proto__" = 54321, ok = 1 } }',
		);
		const config = await loadConfig({ files: paths, env: {} });
		const refusals = await refusalsOf(
			assemble({ modules: [limits], config, runtime: quietRuntime() }),
		);
		expect(refusals.map((r) => r.where)).toEqual(["m.limits"]);
		expect(JSON.stringify(refusals)).not.toContain("54321");
	});

	it("converts an environment string inside a record of objects, as federation-grants' connections take it", async () => {
		const connections = defineModule(
			{
				name: "m",
				section: z.strictObject({
					connections: z.record(
						z.string(),
						z.strictObject({ "max-seconds": z.number().int(), subsets: z.boolean() }),
					),
				}),
				takes: [],
			},
			(m) => [m.provide(seen).by((c) => c.section)],
		);
		const paths = await files(
			// biome-ignore lint/suspicious/noTemplateCurlyInString: HOCON substitutions, not a template
			"kernel.deployment = single\nm.connections.api { max-seconds = ${?MAX}, subsets = ${?SUBSETS} }",
		);
		const config = await loadConfig({ files: paths, env: { MAX: "3600", SUBSETS: "on" } });
		const app = await assemble({ modules: [connections], config, runtime: quietRuntime() });
		expect(app.get(seen)).toEqual({ connections: { api: { "max-seconds": 3600, subsets: true } } });
	});

	it("refuses a key that names an object's prototype with the section's other refusals", async () => {
		const limits = defineModule({
			name: "m",
			section: z.strictObject({ limits: z.record(z.string(), z.number()), n: z.number() }),
			takes: [],
		});
		const paths = await files(
			'kernel.deployment = single\nm { limits { "__proto__" = 5 }, n = "x" }',
		);
		const config = await loadConfig({ files: paths, env: {} });
		const refusals = await refusalsOf(
			assemble({ modules: [limits], config, runtime: quietRuntime() }),
		);
		expect(refusals.map((r) => r.where).sort()).toEqual(["m.limits", "m.n"]);
	});

	it("refuses a value that does not convert, by path and kind only", async () => {
		const refusals = await refusalsOf(boot({ PORT: "80x", TLS: "off" }));
		expect(refusals).toEqual([{ where: "server.port", reason: expect.any(String) }]);
		expect(JSON.stringify(refusals)).not.toContain("80x");
	});
});
