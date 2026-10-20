import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { writeListed } from "../src/contract.ts";
import { fakePackages } from "./fake.ts";

const read = (target: string, path: string) => readFile(join(target, path), "utf8");

it("writes a listed app: its entry and manifest, and kernel's section alone", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeListed(target, ["@mod/http"], fakePackages());

	expect((await readdir(target, { recursive: true })).sort()).toEqual(
		[
			".gitignore",
			"config",
			"config/application.conf",
			"package.json",
			"src",
			"src/main.ts",
		].sort(),
	);
	const manifest = JSON.parse(await read(target, "package.json"));
	expect(Object.keys(manifest.dependencies)).toEqual([
		"@mod/kernel",
		"@mod/config-files",
		"@mod/http",
		"zod",
	]);
	expect(manifest.scripts).toEqual({ start: "node src/main.ts" });
	expect(await read(target, "src/main.ts")).toContain('import m0 from "@o3co/x-http/module";');
	expect(JSON.parse(await read(target, "config/application.conf"))).toEqual(kernelConfig());
	expect(await read(target, ".gitignore")).toBe("node_modules/\nconfig/local*.conf\n");
});

it("adds the reseal entry when seal is listed", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeListed(target, ["@mod/seal"], fakePackages());

	expect(JSON.parse(await read(target, "package.json")).scripts.reseal).toBe("node src/reseal.ts");
	expect(await read(target, "src/reseal.ts")).toContain('from "@o3co/x-seal"');
});

it("refuses a target that holds anything, and writes nothing", async () => {
	const target = await mkdtemp(join(tmpdir(), "app-output-"));
	await writeFile(join(target, "kept"), "");
	await expect(writeListed(target, ["@mod/http"], fakePackages())).rejects.toThrow("not empty");
	expect(await readdir(target)).toEqual(["kept"]);
});
