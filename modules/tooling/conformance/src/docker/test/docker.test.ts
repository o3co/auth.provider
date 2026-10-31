import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { dockerAsync, dockerSync } from "../docker.ts";

// A `docker` of its own first on the path: one that never answers, or one that fails at once.
const bin = mkdtempSync(join(tmpdir(), "conformance-docker-"));
afterAll(() => rmSync(bin, { recursive: true, force: true }));
afterEach(() => vi.unstubAllEnvs());
/** The client this test runs, answering as `script` does; `exec`, so the one killed is the one holding its streams. */
const client = (script: string) => {
	const path = join(bin, "docker");
	writeFileSync(path, `#!/bin/sh\n${script}\n`);
	chmodSync(path, 0o755);
	vi.stubEnv("PATH", `${bin}${delimiter}${process.env.PATH ?? ""}`);
};

describe("a docker call", () => {
	it("is ended at its deadline, holding the process no longer, and says which call it was", async () => {
		client("exec sleep 30");
		const started = performance.now();
		expect(() => dockerSync("control", ["kill", "-s", "KILL", "n"], { within: 200 })).toThrow(
			"docker kill gave no answer within 0.2 seconds",
		);
		expect(() => dockerSync("control", ["image", "inspect", "t"], { within: 200 })).toThrow(
			"docker image inspect gave no answer within 0.2 seconds",
		);
		await expect(dockerAsync("run", ["network", "create", "x"], 200)).rejects.toThrow(
			"docker network create gave no answer within 0.2 seconds",
		);
		expect(performance.now() - started).toBeLessThan(5_000);
	});

	it("fails as the client failed where it answers in time", async () => {
		client('echo "no such container" >&2; exit 3');
		expect(() => dockerSync("control", ["rm", "-f", "n"])).toThrow(/no such container/);
		await expect(dockerAsync("control", ["rm", "-f", "n"])).rejects.toThrow(/no such container/);
	});

	it("answers what the client wrote", async () => {
		client('echo "6379/tcp -> 127.0.0.1:32768"');
		expect(dockerSync("control", ["port", "n", "6379/tcp"]).trim()).toBe(
			"6379/tcp -> 127.0.0.1:32768",
		);
		expect((await dockerAsync("run", ["run", "-d", "redis"])).trim()).toBe(
			"6379/tcp -> 127.0.0.1:32768",
		);
	});
});
