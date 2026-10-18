import { readFileSync } from "node:fs";
import { expect, it, vi } from "vitest";
import { root } from "../../../test/full-app.ts";
import {
	auditReferenceFile,
	auditReferenceOf,
	declarationsIn,
	unlikeKinds,
} from "../audit-events.ts";

// These tests read the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

it("lists each module's declared events in code point order, with their attributes and when they are recorded", () => {
	const reference = auditReferenceOf([
		{
			owner: "@mod/thing",
			events: {
				"thing.made": { attributes: ["client", "scope"], when: "a thing is made | kept" },
				"thing.lost": { attributes: [], when: "a thing is lost" },
			},
		},
	]);
	expect(reference).toContain(
		"| `thing.lost` |  | a thing is lost |\n| `thing.made` | `client`, `scope` | a thing is made \\| kept |",
	);
});

it("holds, committed, the reference generated from the workspace as it is now", async () => {
	expect(readFileSync(auditReferenceFile(root), "utf8")).toBe(
		auditReferenceOf(await declarationsIn(root)),
	);
});

it("lets two modules declare one kind only alike, so a kind holds one meaning", async () => {
	const made = { attributes: ["client"], when: "a thing is made" };
	const declaring = (owner: string, declared: { attributes: string[]; when: string }) => ({
		owner,
		events: { "thing.made": declared },
	});
	expect(unlikeKinds([declaring("@mod/a", made), declaring("@mod/b", { ...made })])).toEqual([]);
	expect(
		unlikeKinds([
			declaring("@mod/a", made),
			declaring("@mod/b", { ...made, attributes: ["other"] }),
		]),
	).toEqual(["thing.made: @mod/a and @mod/b declare it differently"]);
	expect(unlikeKinds(await declarationsIn(root))).toEqual([]);
});
