import { existsSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { linkBuilt } from "../src/link.ts";
import { manifest, tree } from "./fixture.ts";

describe("a project of the bundles built here, as a release installs them", () => {
	it("links each bundle by its public name, and each outside package from a member that holds it", () => {
		const repo = tree({
			"dist/bundles/oauth/package.json": manifest(
				"@o3co/auth-provider-oauth",
				{},
				{
					dependencies: { "@o3co/auth-provider-foundation": "0.19.2", jose: "6.2.0" },
					peerDependencies: { zod: "^4" },
				},
			),
			"dist/bundles/foundation/package.json": manifest("@o3co/auth-provider-foundation", {}),
			"modules/oauth/tokens/node_modules/jose/package.json": "{}",
			"modules/foundation/kernel/node_modules/zod/package.json": "{}",
		});
		const project = join(repo, "project");
		linkBuilt({ bundles: join(repo, "dist", "bundles"), repo, project });
		const at = (name: string) => realpathSync(join(project, "node_modules", name));
		expect(at("@o3co/auth-provider-oauth")).toBe(realpathSync(join(repo, "dist/bundles/oauth")));
		expect(at("@o3co/auth-provider-foundation")).toBe(
			realpathSync(join(repo, "dist/bundles/foundation")),
		);
		expect(at("jose")).toBe(realpathSync(join(repo, "modules/oauth/tokens/node_modules/jose")));
		expect(at("zod")).toBe(realpathSync(join(repo, "modules/foundation/kernel/node_modules/zod")));
		expect(existsSync(join(project, "node_modules", "missing"))).toBe(false);
	});
});
