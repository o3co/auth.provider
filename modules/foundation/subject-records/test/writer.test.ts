import { readFileSync } from "node:fs";
import { subjectWriter } from "@mod/store/subject-writer";
import { expect, it } from "vitest";

const manifest: { exports: Record<string, string> } = JSON.parse(
	readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);

/**
 * Every value reached from `value` through the own data properties of objects, arrays and functions
 * (a class's statics), to `depth`: no function is called, no getter run, no prototype walked.
 */
function reached(value: unknown, depth: number, seen = new Set<unknown>()): unknown[] {
	const holds = (typeof value === "object" && value !== null) || typeof value === "function";
	if (!holds || seen.has(value) || depth === 0) return [value];
	seen.add(value);
	const inner = Reflect.ownKeys(value as object)
		.filter((key) => key !== "prototype")
		.flatMap((key) => {
			const property = Object.getOwnPropertyDescriptor(value, key);
			return property && "value" in property ? reached(property.value, depth - 1, seen) : [];
		});
	return [value, ...inner];
}

it("hands the subject writer on from no entry, at any depth its exported values reach", async () => {
	const entries = Object.values(manifest.exports);
	expect(entries.length).toBeGreaterThan(0);
	for (const entry of entries) {
		const offered = await import(new URL(`../${entry}`, import.meta.url).href);
		expect(reached(offered, 8)).not.toContain(subjectWriter);
	}
});

it("finds the writer where a value would hand it on", () => {
	class Holder {
		static kept = { deep: [subjectWriter] };
	}
	expect(reached({ Holder }, 8)).toContain(subjectWriter);
	expect(reached({ Holder }, 2)).not.toContain(subjectWriter);
});
