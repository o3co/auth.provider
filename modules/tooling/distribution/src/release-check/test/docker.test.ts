import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { docker } from "../docker.ts";

/** Puts a `docker` client running `script` first on the PATH. */
const client = (script: string) => {
	const dir = mkdtempSync(join(tmpdir(), "docker-client-"));
	const file = join(dir, "docker");
	writeFileSync(file, `#!/bin/sh\n${script}\n`);
	chmodSync(file, 0o755);
	vi.stubEnv("PATH", `${dir}:${process.env.PATH}`);
};

afterEach(() => {
	vi.unstubAllEnvs();
});

describe("a docker command", () => {
	it("answers what the client wrote, trimmed", () => {
		client('echo "  $1 $2  "');
		expect(docker(["inspect", "simple-web-1"])).toBe("inspect simple-web-1");
	});

	it("fails as the client failed, what it told kept for the caller", () => {
		client('echo "Error response from daemon: No such container: $2" >&2; exit 1');
		expect(() => docker(["stop", "simple-web-1"])).toThrow(
			expect.objectContaining({
				stderr: expect.stringContaining("No such container: simple-web-1"),
			}),
		);
	});

	it("fails once its deadline passes where the client hangs, the client killed", () => {
		client("exec sleep 30");
		const began = Date.now();
		expect(() => docker(["exec", "simple-web-1", "true"], 200)).toThrow(
			"docker exec did not answer within 0.2 seconds",
		);
		expect(Date.now() - began).toBeLessThan(5_000);
	});
});
