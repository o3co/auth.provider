import { expect, it } from "vitest";
import { fragmentsOf, localConfExample, type Sampled, sampleLines } from "../contract.ts";

const owner: Sampled = { name: "@c/owner", takes: [{ map: "owner.entries", of: "@c/contract" }] };
const typed = (name: string, text: string): Sampled => ({
	name,
	sampleOf: "@c/contract",
	sample: { from: `${name}/entry.example`, text },
});
const first = typed("@c/first", 'type = "first"\nurl = "https://first.example.invalid"\n');
const second = typed("@c/second", 'type = "second"\nsecret = "REPLACE-SECRET"\nscopes = ["a"]\n');

it("writes each composed type's sample under the map its owner takes it for, in the packages' order, as comments a copy reads back", () => {
	const example = localConfExample([], sampleLines([owner, first, second]));
	expect(example).not.toMatch(/^[^#]/m);
	const copy = example
		.split("\n")
		.filter((line) => !line.startsWith("## "))
		.map((line) => line.replace(/^# /, ""))
		.join("\n");
	expect(fragmentsOf([{ from: "copy", text: `${copy}\n` }])).toEqual([
		{
			section: "owner",
			tree: {
				entries: {
					first: { type: "first", url: "https://first.example.invalid" },
					second: { type: "second", secret: "REPLACE-SECRET", scopes: ["a"] },
				},
			},
		},
	]);
});

it("writes no sample where no composed owner takes its contract, and none for a map no sample is for", () => {
	expect(sampleLines([first, second])).toEqual([]);
	expect(sampleLines([owner])).toEqual([]);
	expect(
		sampleLines([{ ...owner, takes: [{ map: "owner.entries", of: "@c/other" }] }, first]),
	).toEqual([]);
});

it("reads a sample as data, and refuses one without its type, a second of one type for a map, and a map at no dotted key", () => {
	expect(() => sampleLines([owner, typed("@c/s", 'type = "s"\nurl = ${HOME}\n')])).toThrow(
		"@c/s/entry.example: a substitution",
	);
	expect(() => sampleLines([owner, typed("@c/u", 'url = "https://u.example.invalid"\n')])).toThrow(
		"@c/u/entry.example: not one entry's keys with its type",
	);
	expect(() => sampleLines([owner, first, typed("@c/again", 'type = "first"\n')])).toThrow(
		"@c/again/entry.example: a second sample of first for owner.entries",
	);
	expect(() =>
		sampleLines([{ ...owner, takes: [{ map: "Owner entries", of: "@c/contract" }] }, first]),
	).toThrow("Owner entries: not a dotted key a map can be at");
});
