import { describe, expect, it } from "vitest";
import { entriesOf } from "../src/entries.ts";
import { manifest, tree } from "./fixture.ts";

const types = (path: string) => ({ types: `./${path}.d.ts`, default: `./${path}.js` });

describe("the entries of a site", () => {
	it("takes each shipped bundle's members' contracts, by their public names, and nothing else", () => {
		const project = tree({
			"node_modules/@o3co/auth-provider-oauth/package.json": manifest("@o3co/auth-provider-oauth", {
				"./tokens": types("tokens/src/contract"),
				"./tokens/testing": types("tokens/src/testing"),
				"./tokens/module": types("tokens/src/module"),
				"./tokens/audit-events": types("tokens/src/audit-events"),
				"./acr": types("acr/src/contract"),
			}),
			// Adapters and wirings offer compositions and stand-ins alone: no contract to read.
			"node_modules/@o3co/auth-provider-templates/package.json": manifest(
				"@o3co/auth-provider-templates",
				{ "./tokens-store/module": types("tokens-store/src/module") },
			),
			"node_modules/@o3co/create-auth-provider/package.json": JSON.stringify({
				name: "@o3co/create-auth-provider",
				bin: { "create-auth-provider": "./bin.js" },
			}),
			"node_modules/@o3co/kept/package.json": manifest(
				"@o3co/kept",
				{ "./inside": types("inside/src/contract") },
				{ private: true },
			),
			"node_modules/zod/package.json": manifest("zod", { "./mini": types("mini") }),
		});
		expect(entriesOf(project)).toEqual([
			"@o3co/auth-provider-oauth/acr",
			"@o3co/auth-provider-oauth/tokens",
		]);
	});
});
