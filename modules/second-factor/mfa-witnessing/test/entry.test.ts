import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import type { Backfilled } from "../src/contract.ts";

/** Every answer `settle` may give: a key missing or one too many does not typecheck. */
const answers: Record<Backfilled, true> = {
	marked: true,
	held: true,
	none: true,
	unclaimed: true,
	inconsistent: true,
};

it("declares the witness-backfill script, counting each answer settle may give and no other", () => {
	const manifest = JSON.parse(
		readFileSync(join(import.meta.dirname, "..", "package.json"), "utf8"),
	);
	const [entry] = manifest.appEntries;
	expect(entry).toMatchObject({
		script: "witness-backfill",
		shape: "settle-subjects",
		contract: "witnessBackfill",
		member: "settle",
	});
	expect([...entry.answers].sort()).toEqual(Object.keys(answers).sort());
	expect(entry.answers).toHaveLength(Object.keys(answers).length);
});
