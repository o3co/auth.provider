import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { artifactsOf, keptThenStopped, stopAll } from "../harness.ts";

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

	it("runs every stop, in reverse, though some fail, and answers each failure", async () => {
		const ran: string[] = [];
		const problems = await stopAll([
			async () => void ran.push("suite"),
			async () => {
				ran.push("front");
				throw new Error("front would not stop");
			},
			async () => void ran.push("app"),
		]);
		expect(ran).toEqual(["app", "front", "suite"]);
		expect(problems.map(String)).toEqual(["Error: front would not stop"]);
	});
});
