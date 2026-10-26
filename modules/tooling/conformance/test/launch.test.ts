import { tmpdir } from "node:os";
import { expect, it } from "vitest";
import { baseEnv, freePort, launch } from "../src/driver.ts";

/** A target that answers http at `port` and goes on running whatever SIGTERM asks. */
const deaf = (port: number) =>
	[
		"process.on('SIGTERM', () => {});",
		`require('node:http').createServer((q, r) => r.end('up')).listen(${port}, '127.0.0.1');`,
	].join("\n");

it("kills a target that goes on past its time after SIGTERM, and is stopped once it is gone", async () => {
	const port = await freePort();
	const started = await launch({
		command: process.execPath,
		args: ["-e", deaf(port)],
		cwd: tmpdir(),
		env: baseEnv(),
		port,
		stopGraceMs: 200,
	});
	if (started.kind !== "running") throw new Error(`refused: ${started.output}`);
	const asked = Date.now();
	await started.stop();
	expect(Date.now() - asked).toBeLessThan(5_000);
	// Nothing answers where it listened.
	await expect(fetch(started.baseUrl, { signal: AbortSignal.timeout(500) })).rejects.toThrow();
});
