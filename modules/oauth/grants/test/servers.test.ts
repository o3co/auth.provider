import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { grantServers } from "../src/contract.ts";

/** Each grant type a workspace package's manifest declares it serves, by that module's name: its package's, without the scope. */
async function declared(): Promise<Record<string, string>> {
	const modules = join(import.meta.dirname, "..", "..", "..");
	const found: Record<string, string> = {};
	for (const area of await readdir(modules, { withFileTypes: true })) {
		if (!area.isDirectory()) continue;
		for (const dir of await readdir(join(modules, area.name), { withFileTypes: true })) {
			if (!dir.isDirectory()) continue;
			const text = await readFile(join(modules, area.name, dir.name, "package.json"), "utf8").catch(
				() => undefined,
			);
			if (text === undefined) continue;
			const manifest = JSON.parse(text) as { name: string; grantTypes?: string[] };
			for (const type of manifest.grantTypes ?? []) {
				expect(found[type], `${type} declared twice`).toBeUndefined();
				found[type] = manifest.name.replace(/^@mod\//, "");
			}
		}
	}
	return found;
}

it("indexes each first-party grant type by the module that declares it serves it, and no other", async () => {
	expect({ ...grantServers }).toEqual(await declared());
});

it("names no module for a name every object has, as for any type it does not list", () => {
	for (const name of ["constructor", "__proto__", "toString", "hasOwnProperty"])
		expect(grantServers[name], name).toBeUndefined();
});
