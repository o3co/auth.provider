import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { releaseOf } from "../src/workspace.ts";

const workspace = (manifest: object, readme?: string) => {
	const root = mkdtempSync(join(tmpdir(), "workspace-"));
	writeFileSync(join(root, "package.json"), JSON.stringify(manifest));
	if (readme !== undefined) writeFileSync(join(root, "README.md"), readme);
	return root;
};

it("reads the release from the workspace: version, license, repository, keywords and the README's notice", () => {
	const root = workspace(
		{
			version: "0.18.0",
			license: "Apache-2.0",
			engines: { node: ">=24" },
			repository: { type: "git", url: "https://github.com/o3co/auth.provider" },
			keywords: ["oauth2", "oidc"],
		},
		"# Title\n\nText.\n\nCopyright 2026 Example Ltd. Licensed under the Apache License, Version 2.0.\n",
	);
	expect(releaseOf(root)).toEqual({
		version: "0.18.0",
		license: "Apache-2.0",
		engines: { node: ">=24" },
		repository: "https://github.com/o3co/auth.provider",
		notice: "Copyright 2026 Example Ltd. Licensed under the Apache License, Version 2.0.",
		keywords: ["oauth2", "oidc"],
	});
});

it("leaves out what the workspace does not state, and answers none without a version", () => {
	expect(releaseOf(workspace({ version: "0.18.0", repository: "https://example.test/r" }))).toEqual(
		{
			version: "0.18.0",
			repository: "https://example.test/r",
		},
	);
	expect(releaseOf(workspace({ name: "x" }, "Copyright nobody\n"))).toBeUndefined();
});
