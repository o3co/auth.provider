import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { indexSite, versionDir } from "../src/site.ts";
import { tree } from "./fixture.ts";

describe("a site of every minor's API", () => {
	it("keeps a minor in one dir, a patch writing over it, and takes no prerelease", () => {
		expect(versionDir("0.19.2")).toBe("v0.19");
		expect(versionDir("1.0.0")).toBe("v1.0");
		for (const version of ["0.19.0-rc.1", "0.19", "v0.19.0", "next"]) {
			expect(() => versionDir(version), version).toThrow(version);
		}
	});

	it("points the root at the newest minor by number, and lists every one newest first", () => {
		const site = tree({
			"v0.9/index.html": "",
			"v0.19/index.html": "",
			"v0.20/index.html": "",
			"v1.0/index.html": "",
			"legacy/index.html": "",
			"v0.18.4/index.html": "",
		});
		indexSite(site);
		const index = readFileSync(join(site, "index.html"), "utf8");
		expect(index).toContain('url=v1.0/"');
		const versions = readFileSync(join(site, "versions.html"), "utf8");
		const listed = [...versions.matchAll(/href="(v[^/"]+)\/"/g)].map((m) => m[1]);
		expect(listed).toEqual(["v1.0", "v0.20", "v0.19", "v0.9"]);
	});
});
