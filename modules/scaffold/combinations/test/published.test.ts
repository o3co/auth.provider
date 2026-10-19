import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { published } from "../src/contract.ts";
import { publishedInIndex, publishedWith } from "../src/published.ts";

/** An index as distribution writes it: each member's name, its bundle, its entry and its manifest. */
function indexWith(packages: readonly { name: string; bundle: string; dir: string }[]) {
	const file = join(mkdtempSync(join(tmpdir(), "combinations-published-")), "index.json");
	const entries = packages.map(({ name, bundle, dir }) => ({
		name,
		package: bundle,
		entry: `${bundle}/${dir}`,
		manifest: { name, kind: "feature", exports: { "./module": "./src/module.ts" } },
	}));
	writeFileSync(file, JSON.stringify({ version: "0.18.0", packages: entries }));
	return file;
}

const index = publishedInIndex(
	indexWith([
		{ name: "@mod/tokens", bundle: "@o3co/auth-provider-oauth", dir: "tokens" },
		{ name: "@mod/http", bundle: "@o3co/auth-provider-foundation", dir: "http" },
		{ name: "@mod/kernel", bundle: "@o3co/auth-provider-foundation", dir: "kernel" },
	]),
);

it("gives each name given its published bundle and the path its entries import under, in the order given", () => {
	expect(publishedWith(index, ["@mod/http", "@mod/tokens", "@mod/kernel"])).toEqual([
		{
			name: "@mod/http",
			package: "@o3co/auth-provider-foundation",
			entry: "@o3co/auth-provider-foundation/http",
		},
		{
			name: "@mod/tokens",
			package: "@o3co/auth-provider-oauth",
			entry: "@o3co/auth-provider-oauth/tokens",
		},
		{
			name: "@mod/kernel",
			package: "@o3co/auth-provider-foundation",
			entry: "@o3co/auth-provider-foundation/kernel",
		},
	]);
});

it("refuses, naming each, a name no bundle publishes", () => {
	expect(() => publishedWith(index, ["@mod/http", "@mod/nope", "@mod/gone"])).toThrow(
		"@mod/nope: not published; @mod/gone: not published",
	);
});

it("refuses in the workspace, where nothing is published and every name imports as itself", () => {
	expect(() => publishedWith(undefined, ["@mod/http"])).toThrow(/nothing is published/);
	// These tests run in the workspace, with no index at the bundle's root.
	expect(() => published(["@mod/http"])).toThrow(/nothing is published/);
});
