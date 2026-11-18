import { readFileSync } from "node:fs";
import { subjectWriter } from "@mod/store/subject-writer";
import { expect, it } from "vitest";

const manifest: { exports: Record<string, string> } = JSON.parse(
	readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

/**
 * Each value a module offers, read from its namespace by name (a namespace's export names are
 * enumerable; vitest serves them as accessors, which reading by name runs as an import does).
 */
const offeredBy = (namespace: Record<string, unknown>) =>
	Object.keys(namespace).map((name) => namespace[name]);

/**
 * Every value reached from `roots` through the own data properties of objects, arrays and functions
 * (a class's statics), each visited once, however deep: no function is called, no getter run, no
 * prototype walked, and no Map or Set opened.
 */
function reached(roots: readonly unknown[]): Set<unknown> {
	const seen = new Set<unknown>();
	const next = [...roots];
	while (next.length > 0) {
		const value = next.shift();
		if (seen.has(value)) continue;
		seen.add(value);
		if ((typeof value !== "object" || value === null) && typeof value !== "function") continue;
		for (const key of Reflect.ownKeys(value)) {
			if (key === "prototype") continue;
			const property = Object.getOwnPropertyDescriptor(value, key);
			if (property && "value" in property) next.push(property.value);
		}
	}
	return seen;
}

it("hands the subject writer from no entry: no export, and nothing its exports hold as data, is the writer", async () => {
	const entries = Object.entries(manifest.exports);
	expect(entries.length).toBeGreaterThan(0);
	for (const [entry, file] of entries) {
		const namespace = await import(new URL(`../${file}`, import.meta.url).href);
		const offered = offeredBy(namespace);
		// Every export is a root of the walk: it cannot pass having read none.
		expect(offered.length, entry).toBeGreaterThan(0);
		expect(reached(offered).has(subjectWriter), entry).toBe(false);
	}
});

it("finds the writer an imported module hands on: exported itself, nested in data, or a class's static", async () => {
	const namespace = await import("./fixtures/handing-on.ts");
	for (const name of ["direct", "nested", "Holder"] as const) {
		expect(reached(offeredBy({ [name]: namespace[name] })).has(subjectWriter), name).toBe(true);
	}
});

it("finds the writer however the walk first met what holds it", () => {
	const shared = { deep: [subjectWriter] };
	const offered = { a: { b: { c: { d: { e: { f: shared } } } } }, b: shared };
	expect(reached([offered]).has(subjectWriter)).toBe(true);
});
