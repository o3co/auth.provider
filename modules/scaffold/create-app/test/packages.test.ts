import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { packagesFor } from "../src/packages.ts";
import { workspacePackages } from "../src/project.ts";

/** An index as distribution writes it into a bundle: members' manifests, public names and examples. */
const indexed = () => {
	const file = join(mkdtempSync(join(tmpdir(), "create-app-")), "index.json");
	const entry = (name: string, bundle: string, fragment?: string) => ({
		name: `@mod/${name}`,
		package: `@o3co/auth-provider-${bundle}`,
		entry: `@o3co/auth-provider-${bundle}/${name}`,
		manifest: { name: `@mod/${name}` },
		...(fragment ? { fragment } : {}),
	});
	writeFileSync(
		file,
		JSON.stringify({
			version: "0.18.0",
			packages: [
				entry("kernel", "foundation", 'kernel {\n  deployment = "REPLACE-DEPLOYMENT"\n}\n'),
				entry("tokens", "oauth"),
				entry("authorize", "oauth", 'authorize {\n  login-page = "REPLACE-LOGIN-PAGE"\n}\n'),
			],
		}),
	);
	return file;
};

it("names a bundle's packages publicly, depending on each bundle once at the index's version", async () => {
	const packages = packagesFor({}, indexed());
	expect(packages.dependencies(["@mod/kernel", "@mod/tokens", "@mod/authorize"])).toEqual({
		"@o3co/auth-provider-foundation": "0.18.0",
		"@o3co/auth-provider-oauth": "0.18.0",
	});
	expect(packages.importOf("@mod/tokens")).toBe("@o3co/auth-provider-oauth/tokens");
	expect(await packages.fragments(["@mod/kernel", "@mod/tokens", "@mod/authorize"])).toEqual([
		{ section: "kernel", tree: { deployment: "REPLACE-DEPLOYMENT" } },
		{ section: "authorize", tree: { "login-page": "REPLACE-LOGIN-PAGE" } },
	]);
	expect(() => packages.dependencies(["@mod/nowhere"])).toThrow(
		"@mod/nowhere is no published package",
	);
});

it("links the workspace's packages where one is given, naming them as the workspace does", async () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..");
	const packages = packagesFor({ workspace: root }, join(tmpdir(), "no-index.json"));
	const kernelDir = workspacePackages(root).get("@mod/kernel");
	expect(packages.dependencies(["@mod/kernel"])).toEqual({ "@mod/kernel": `link:${kernelDir}` });
	expect(packages.importOf("@mod/kernel")).toBe("@mod/kernel");
	expect((await packages.fragments(["@mod/kernel"])).map((f) => f.section)).toEqual(["kernel"]);
}, 30_000);

it("takes the workspace it lies in, with no index and no workspace given", async () => {
	const packages = packagesFor({}, join(tmpdir(), "no-index.json"));
	expect(packages.dependencies(["@mod/kernel"])).toEqual({ "@mod/kernel": "*" });
	expect((await packages.fragments(["@mod/kernel"])).map((f) => f.section)).toEqual(["kernel"]);
}, 30_000);
