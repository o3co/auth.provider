/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */
import {
	existsSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	rmSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { copyTemplates, listTemplates } from "../../scripts/templates.mjs";
import { availableTemplates } from "../index.mjs";

// What a template is has two readers: the build-time copy (and CI, which asks
// the same module) and the scaffolder, which reads what the copy shipped. A
// template one of them skips and the other takes is shipped untested or tested
// unshipped — so both are held to the same fixture here.

const template = (root: string, name: string, files: Record<string, string> = {}): void => {
	mkdirSync(join(root, name), { recursive: true });
	writeFileSync(join(root, name, "package.json"), `{"name":"${name}"}\n`);
	for (const [path, content] of Object.entries(files)) {
		mkdirSync(join(root, name, path, ".."), { recursive: true });
		writeFileSync(join(root, name, path), content);
	}
};

describe("what a template is", () => {
	let root: string;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "create-auth-provider-templates-lib-"));
		template(root, "zeta");
		template(root, "alpha");
		// Each of these looks like a template in one way and is not one.
		template(root, ".hidden");
		mkdirSync(join(root, "no-manifest"));
		writeFileSync(join(root, "versions.json"), "{}\n");
		symlinkSync(join(root, "alpha"), join(root, "linked"), "dir");
	});

	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});

	it("is a directory, not a link and not dot-named, holding a package.json", () => {
		expect(listTemplates(root)).toEqual(["alpha", "zeta"]);
	});

	it("reads the same to the scaffolder as to the build", () => {
		expect(availableTemplates(root)).toEqual(listTemplates(root));
	});

	it("has a lowercase kebab-case name, or the build refuses it by name", () => {
		// The name is a CLI argument and a Docker image tag in CI; a tag is
		// lowercase only.
		template(root, "Not_Kebab");
		expect(() => listTemplates(root)).toThrow(/Not_Kebab/);
	});

	it.each(["trailing-", "double--hyphen", "-leading"])(
		"refuses %s: a hyphen separates two non-empty parts",
		(name) => {
			// `trailing-` would make CI's image tag `scaffold-node-base-trailing-`,
			// which Docker refuses.
			template(root, name);
			expect(() => listTemplates(root)).toThrow(name);
		},
	);

	it.each(["m2m", "web-bff", "a1-b2-c3"])("takes %s", (name) => {
		template(root, name);
		expect(listTemplates(root)).toContain(name);
	});

	it("is required: a templates directory holding none refuses the build", () => {
		const empty = join(root, "empty");
		mkdirSync(empty);
		expect(() => listTemplates(empty)).toThrow(/no template/);
	});
});

describe("copyTemplates", () => {
	let src: string;
	let dest: string;

	beforeEach(() => {
		src = mkdtempSync(join(tmpdir(), "create-auth-provider-copy-src-"));
		dest = mkdtempSync(join(tmpdir(), "create-auth-provider-copy-dest-"));
		template(src, "alpha", {
			"src/app.mts": "// alpha\n",
			".gitignore": ".env\n",
			"node_modules/dep/index.js": "",
			"dist/app.mjs": "",
		});
		template(src, "beta", { "src/app.mts": "// beta\n" });
		// What the last build left: a template since removed from the repository.
		template(dest, "removed");
	});

	afterEach(() => {
		rmSync(src, { recursive: true, force: true });
		rmSync(dest, { recursive: true, force: true });
	});

	it("copies every template and returns their names", () => {
		expect(copyTemplates(src, dest)).toEqual(["alpha", "beta"]);
		expect(readFileSync(join(dest, "alpha", "src", "app.mts"), "utf-8")).toBe("// alpha\n");
		expect(readFileSync(join(dest, "beta", "src", "app.mts"), "utf-8")).toBe("// beta\n");
	});

	it("rebuilds the destination whole, so a removed template does not linger", () => {
		copyTemplates(src, dest);
		expect(readdirSync(dest).sort()).toEqual(["alpha", "beta"]);
	});

	it("leaves out each template's node_modules and dist", () => {
		copyTemplates(src, dest);
		expect(existsSync(join(dest, "alpha", "node_modules"))).toBe(false);
		expect(existsSync(join(dest, "alpha", "dist"))).toBe(false);
	});

	it("stages each .gitignore under a name npm publishes (#407)", () => {
		copyTemplates(src, dest);
		expect(existsSync(join(dest, "alpha", ".gitignore"))).toBe(false);
		expect(readFileSync(join(dest, "alpha", "gitignore"), "utf-8")).toBe(".env\n");
	});
});
