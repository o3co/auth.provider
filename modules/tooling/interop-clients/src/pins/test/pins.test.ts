import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { jarsIn, pinProblems, pinsText } from "../pins.ts";

describe("the pinned jars", () => {
	const dir = mkdtempSync(join(tmpdir(), "interop-pins-"));
	writeFileSync(join(dir, "a.jar"), "a");
	writeFileSync(join(dir, "b.jar"), "b");
	writeFileSync(join(dir, "notes.txt"), "not a jar");
	const jars = jarsIn(dir);

	it("are each jar's SHA-256, written as sha256sum writes them", () => {
		expect(jars.map((j) => j.file)).toEqual(["a.jar", "b.jar"]);
		expect(pinsText(jars)).toBe(
			"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  a.jar\n" +
				"3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d  b.jar\n",
		);
		expect(pinProblems(jars, pinsText(jars))).toEqual([]);
	});

	it("refuse a jar whose hash changed, one not pinned, and a pinned one missing", () => {
		const pins = `${"0".repeat(64)}  a.jar\n${"1".repeat(64)}  c.jar\n`;
		expect(pinProblems(jars, pins)).toEqual([
			`a.jar: its SHA-256 is ${jars[0]?.sha256}, not the pinned ${"0".repeat(64)}`,
			"b.jar: not pinned",
			"c.jar: pinned, and not there",
		]);
	});
});
