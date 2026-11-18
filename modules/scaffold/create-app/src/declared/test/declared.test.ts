import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { packagesFor } from "../../packages.ts";

/** A member's declarations for the guide, as its manifest holds them. */
const declared = {
	name: "@mod/audit-http",
	adapts: "@mod/audit",
	registersAs: "http",
	asks: ["Audit events posted to a receiver (`audit-http.url`)."],
};
/** The workspace this test lies in, linked with no index. */
const root = join(import.meta.dirname, "..", "..", "..", "..", "..", "..");
const noIndex = join(tmpdir(), "no-index.json");
const linked = () => packagesFor({ workspace: root }, noIndex);
/** A map an owner takes entry samples for, and a type's sample of its contract. */
const taken = [{ map: "owner.entries", of: "@mod/c" }];
const sample = 'type = "typed"\n';
/** An index as distribution writes it into a bundle: members' manifests and public names, with what they declare. */
const indexed = () => {
	const file = join(mkdtempSync(join(tmpdir(), "create-app-")), "index.json");
	const entry = (name: string, bundle: string) => ({
		name: `@mod/${name}`,
		package: `@o3co/auth-provider-${bundle}`,
		entry: `@o3co/auth-provider-${bundle}/${name}`,
		manifest: { name: `@mod/${name}` },
	});
	writeFileSync(
		file,
		JSON.stringify({
			version: "0.18.0",
			repository: "https://github.com/o3co/auth.provider",
			packages: [
				entry("tokens", "oauth"),
				{ ...entry("audit-http", "audit-receivers"), manifest: declared },
				{ ...entry("owner", "up"), manifest: { name: "@mod/owner", takesSamples: taken } },
				{ ...entry("typed", "up"), manifest: { name: "@mod/typed", sampleOf: "@mod/c" }, sample },
			],
		}),
	);
	return file;
};

it("gives what each module declares for the guide and of entry samples, from the index's manifests or the workspace's", () => {
	const published = packagesFor({}, indexed());
	expect(published.asks?.(["@mod/audit-http", "@mod/tokens", "@mod/nowhere"])).toEqual([
		declared,
		{ name: "@mod/tokens" },
	]);
	expect(published.samples?.(["@mod/owner", "@mod/typed", "@mod/tokens"])).toEqual([
		{ name: "@mod/owner", takes: taken },
		{ name: "@mod/typed", sampleOf: "@mod/c", sample: { from: "@mod/typed", text: sample } },
		{ name: "@mod/tokens" },
	]);
	expect(linked().asks?.(["@mod/audit-stdout"])).toEqual([
		{ name: "@mod/audit-stdout", adapts: "@mod/audit", registersAs: "stdout" },
	]);
	expect(linked().samples?.(["@mod/tokens"])).toEqual([{ name: "@mod/tokens" }]);
}, 30_000);
