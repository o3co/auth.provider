import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { artifactsOf, keptThenStopped } from "../harness.ts";

describe("a plan run's records and its stops", () => {
	it("keeps each plan's records in a directory of its own under the one named", () => {
		expect(artifactsOf("basic", "/records")).toBe(join("/records", "basic"));
		expect(artifactsOf("config", "/records")).toBe(join("/records", "config"));
		expect(artifactsOf("basic", undefined)).toBeUndefined();
	});

	it("stops what it stops though keeping its records failed, and says the records failed", async () => {
		let stopped = false;
		const stop = keptThenStopped(
			async () => {
				throw new Error("no space left");
			},
			async () => {
				stopped = true;
			},
		);
		await expect(stop()).rejects.toThrow("no space left");
		expect(stopped).toBe(true);
	});
});
