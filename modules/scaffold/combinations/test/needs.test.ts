import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { neededWith } from "../src/composed.ts";
import { declaredInIndex } from "../src/declared.ts";

const module = { "./module": "./src/module.ts" };
const on = (...names: string[]) => Object.fromEntries(names.map((n) => [n, "workspace:*"]));

/** The declarations of a bundle whose index holds these manifests. */
function declaredOf(...manifests: object[]) {
	const file = join(mkdtempSync(join(tmpdir(), "needs-")), "index.json");
	writeFileSync(file, JSON.stringify({ packages: manifests.map((manifest) => ({ manifest })) }));
	return declaredInIndex(file);
}

const mail = { name: "@n/mail", kind: "foundation", exports: module };
const seal = { name: "@n/seal", kind: "foundation", exports: module };
const users = {
	name: "@n/users",
	kind: "feature",
	exports: module,
	dependencies: on("@n/mail"),
	helpers: ["@n/mail"],
};
const federation = {
	name: "@n/federation",
	kind: "feature",
	exports: module,
	dependencies: on("@n/seal"),
	optional: ["@n/seal"],
};
const tokens = {
	name: "@n/tokens",
	kind: "feature",
	exports: module,
	dependencies: on("@n/federation", "@n/seal"),
};

it("needs no module of a dependency used for its helpers, nor of one used only where something contributes", () => {
	const declared = declaredOf(mail, seal, users, federation, tokens);
	expect(neededWith(declared, ["@n/users"])).toEqual(["@n/users"]);
	expect(neededWith(declared, ["@n/federation"])).toEqual(["@n/federation"]);
	// A package that needs it to run brings it, as ever.
	expect(neededWith(declared, ["@n/tokens"])).toEqual(["@n/tokens", "@n/federation", "@n/seal"]);
});

it("refuses helpers or optional that are not a non-empty list of its dependencies, naming each package", () => {
	const odd = { ...users, name: "@n/odd", helpers: "@n/mail" };
	const stray = { ...federation, name: "@n/stray", optional: ["@n/mail"] };
	expect(() => declaredOf(mail, seal, odd, stray)).toThrow(
		"@n/odd: helpers is not a non-empty list of its dependencies; " +
			"@n/stray: optional is not a non-empty list of its dependencies",
	);
});
