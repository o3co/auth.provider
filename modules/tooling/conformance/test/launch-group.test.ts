import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { baseEnv, freePort, launch } from "../src/driver.ts";

/** A server that starts a child of its own, and says the child's pid at `/child`. */
const program = `
import { spawn } from "node:child_process";
import { createServer } from "node:http";
const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
createServer((req, res) => res.end(String(child.pid))).listen(Number(process.env.PORT), "127.0.0.1");
`;
const alive = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
};

describe("a target launched as a group", () => {
	it("is killed with SIGKILL, what it started with it", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-group-"));
		await writeFile(join(dir, "main.mjs"), program);
		const port = await freePort();
		const started = await launch({
			command: process.execPath,
			args: ["main.mjs"],
			cwd: dir,
			env: { ...baseEnv(), PORT: String(port) },
			port,
			group: true,
		});
		if (started.kind !== "running" || !started.kill) throw new Error("not started as a group");
		const child = Number(await (await fetch(`${started.baseUrl}/child`)).text());
		expect(alive(child)).toBe(true);
		const before = performance.now();
		const ended = await started.kill();
		expect(ended.signal).toBe("SIGKILL");
		expect(ended.endedAt).toBeGreaterThanOrEqual(before);
		for (let i = 0; i < 50 && alive(child); i++) await new Promise((r) => setTimeout(r, 20));
		expect(alive(child)).toBe(false);
	});

	it("offers no kill where not launched as a group", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-group-"));
		await writeFile(join(dir, "main.mjs"), program);
		const port = await freePort();
		const started = await launch({
			command: process.execPath,
			args: ["main.mjs"],
			cwd: dir,
			env: { ...baseEnv(), PORT: String(port) },
			port,
		});
		if (started.kind !== "running") throw new Error("not started");
		expect(started.kill).toBeUndefined();
		const child = Number(await (await fetch(`${started.baseUrl}/child`)).text());
		await started.stop();
		process.kill(child, "SIGKILL");
	});
});
