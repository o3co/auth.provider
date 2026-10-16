import { setTimeout as wait } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { processText } from "../defaults.ts";

/** The garbage collections the text counts, of every kind. */
const collections = (text: string) =>
	[...text.matchAll(/^auth_provider_nodejs_gc_duration_seconds_count\{[^}]*\} (\d+)$/gm)]
		.map(([, n]) => Number(n))
		.reduce((a, b) => a + b, 0);

describe("process", () => {
	it("keeps counting from the first read on, in one registry", async () => {
		await processText();
		// Tens of megabytes of short-lived arrays, enough for the young generation to be collected.
		const junk = Array.from({ length: 400 }, (_, i) => new Array<number>(10_000).fill(i));
		junk.length = 0;
		await wait(50);
		expect(collections(await processText())).toBeGreaterThan(0);
	});
});
