import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { hostLibfaketime } from "../clock.ts";

const named = process.env.CONFORMANCE_FAKETIME_LIB;
afterEach(() => {
	if (named === undefined) delete process.env.CONFORMANCE_FAKETIME_LIB;
	else process.env.CONFORMANCE_FAKETIME_LIB = named;
});

describe("the host's libfaketime", () => {
	it("takes a library named only where it moves a Node process's clock, not where a file is there", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-clock-"));
		const notALibrary = join(dir, "libfaketimeMT.so.1");
		await writeFile(notALibrary, "not a library");
		process.env.CONFORMANCE_FAKETIME_LIB = notALibrary;
		expect(hostLibfaketime()).toBeUndefined();
		process.env.CONFORMANCE_FAKETIME_LIB = join(dir, "absent.so");
		expect(hostLibfaketime()).toBeUndefined();
	});
});
