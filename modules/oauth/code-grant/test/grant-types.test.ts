import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";
import { codeGrantType } from "../src/contract.ts";

it("declares in its manifest the grant type it serves, for grants' index of first-party grants", async () => {
	const manifest = JSON.parse(
		await readFile(new URL("../package.json", import.meta.url), "utf8"),
	) as { grantTypes?: unknown };
	expect(manifest.grantTypes).toEqual([codeGrantType]);
});
