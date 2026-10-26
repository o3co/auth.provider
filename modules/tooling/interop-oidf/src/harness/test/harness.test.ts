import { existsSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SuiteStopFailed } from "../../suite/suite.ts";
import { artifactsOf, cleared, keptThenStopped, stopAll } from "../harness.ts";

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

	it("keeps its work directory where the suite's start could not stop the suite, and removes it otherwise", async () => {
		const kept = await mkdtemp(join(tmpdir(), "interop-oidf-work-"));
		const start = new SuiteStopFailed([new Error("no answer")], "the suite's stop failed");
		const problems: unknown[] = [];
		await cleared(kept, start, problems);
		expect(existsSync(kept)).toBe(true);
		expect(problems).toEqual([]);

		const removed = await mkdtemp(join(tmpdir(), "interop-oidf-work-"));
		await cleared(removed, new Error("the app refused to start"), problems);
		expect(existsSync(removed)).toBe(false);

		const stopFailed = await mkdtemp(join(tmpdir(), "interop-oidf-work-"));
		await cleared(stopFailed, undefined, [new Error("the front did not stop")]);
		expect(existsSync(stopFailed)).toBe(true);
	});
});
