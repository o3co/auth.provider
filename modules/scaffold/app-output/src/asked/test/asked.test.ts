import { expect, it } from "vitest";
import { type Asked, askedOf } from "../asked.ts";

const owner: Asked = {
	name: "@mod/owner",
	registersAs: "own",
	asks: [
		"Named in `owner.names = [{adapters}]`.",
		{ line: "`owner.names`: `{adapters}`.", decides: true },
		{ line: "`own` is the owner's own.", decides: true, unadapted: true },
		{ line: "Kept in the configuration.", unadapted: true },
	],
};
const first: Asked = { name: "@mod/first", adapts: "@mod/owner", registersAs: "first" };
const second: Asked = {
	name: "@mod/second",
	adapts: "@mod/owner",
	registersAs: "second",
	asks: ["Sent to a receiver (`second.url`)."],
};

it("renders each composed module's lines in the modules' order, the decided ones apart", () => {
	const lone: Asked = { name: "@mod/lone", asks: ["Lone (`lone.key`)."] };
	expect(askedOf(["@mod/lone", "@mod/owner"], [owner, lone])).toEqual({
		chosen: [
			"- Lone (`lone.key`).",
			"- Named in `owner.names = [own]`.",
			"- Kept in the configuration.",
		],
		decides: ["- `owner.names`: `own`.", "- `own` is the owner's own."],
	});
});

it("fills the mark with the composed adapters' names, leaving out the owner's unadapted lines", () => {
	expect(askedOf(["@mod/owner", "@mod/first", "@mod/second"], [owner, first, second])).toEqual({
		chosen: ["- Named in `owner.names = [first, second]`.", "- Sent to a receiver (`second.url`)."],
		decides: ["- `owner.names`: `first, second`."],
	});
});

it("reads only what is composed: a declaration of a module left out, or an adapter not composed, is none", () => {
	expect(askedOf(["@mod/owner"], [owner, first, second]).chosen).toEqual([
		"- Named in `owner.names = [own]`.",
		"- Kept in the configuration.",
	]);
	expect(askedOf(["@mod/unknown"], [owner])).toEqual({ chosen: [], decides: [] });
});
