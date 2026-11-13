import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { parse } from "yaml";
import { manifestOf, workspaceFile } from "../src/project.ts";

it("pins the pnpm the workspace builds with, so the lockfile reads alike in the image", async () => {
	const root = join(import.meta.dirname, "..", "..", "..", "..", "package.json");
	const workspace = JSON.parse(await readFile(root, "utf8")) as { packageManager: string };
	const app = JSON.parse(manifestOf({})) as { packageManager: string };
	expect(app.packageManager).toBe(workspace.packageManager);
});

it("holds the scripts it is given, and no `scripts` where it is given none", () => {
	const scripts = { start: "node src/main.ts" };
	expect(JSON.parse(manifestOf({}, scripts)).scripts).toEqual(scripts);
	expect(JSON.parse(manifestOf({}))).not.toHaveProperty("scripts");
});

/** What every app installs under, with the setting keeping the lockfile one document. */
const hardened = {
	minimumReleaseAge: 1440,
	trustPolicy: "no-downgrade",
	blockExoticSubdeps: true,
	pmOnFail: "ignore",
};

it("keeps the lockfile one document beside the settings it is given, and says why", () => {
	expect(parse(workspaceFile({}))).toEqual(hardened);
	expect(parse(workspaceFile({ overrides: { zod: "4.6.7" } }))).toEqual({
		overrides: { zod: "4.6.7" },
		...hardened,
	});
	expect(workspaceFile({})).toContain("Dependabot");
});

it("installs every app under the release age, the trust policy and registry dependencies alone, saying why", () => {
	const written = workspaceFile({});
	expect(written.startsWith("#")).toBe(true);
	expect(written).toContain("a hijacked release");
	// What to do when the trust policy refuses: a mirror that keeps the evidence, the package looked at, the exclusion last.
	expect(written).toContain("registry mirror");
	expect(written).toContain("trustPolicyExclude");
	expect(written).toContain("the last resort");
	// A package added, one outside the release among them, that brings a git or tarball dependency.
	expect(written).toContain("replace that package");
});

it("takes a value given for one of those settings in its place, written once", () => {
	// An app beside packages outside the release is given its release age by `outside`.
	const written = workspaceFile({ minimumReleaseAge: 60, minimumReleaseAgeExclude: ["@o3co/x"] });
	expect(written.match(/^minimumReleaseAge:/gm)).toHaveLength(1);
	expect(parse(written)).toEqual({
		minimumReleaseAgeExclude: ["@o3co/x"],
		...hardened,
		minimumReleaseAge: 60,
	});
});
