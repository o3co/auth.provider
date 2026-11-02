import type { SpawnSyncReturns } from "node:child_process";
import { describe, expect, it } from "vitest";
import { succeeded } from "../spawned.ts";

/** A process's answer as spawnSync gives it. */
const answer = (over: Partial<SpawnSyncReturns<string>>): SpawnSyncReturns<string> => ({
	pid: 1,
	output: [],
	stdout: "out",
	stderr: "",
	status: 0,
	signal: null,
	...over,
});

describe("spawned", () => {
	it("takes an answer as succeeded only where it exited 0 with no error, its output whole", () => {
		expect(succeeded(answer({}))).toBe(true);
		expect(succeeded(answer({ status: 1 }))).toBe(false);
		expect(succeeded(answer({ status: null, signal: "SIGTERM" }))).toBe(false);
		// Past the buffer, spawnSync can answer status 0 beside ENOBUFS, its output cut short.
		const cut = Object.assign(new Error("spawnSync git ENOBUFS"), { code: "ENOBUFS" });
		expect(succeeded(answer({ status: 0, error: cut }))).toBe(false);
	});
});
