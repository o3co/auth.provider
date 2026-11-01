import { mkdtemp, readFile, writeFile } from "node:fs/promises";
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

	it("stops what the target started with it too, though the target ends first and what it started holds on past SIGTERM", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-group-"));
		const holding = `
import { spawn } from "node:child_process";
import { createServer } from "node:http";
const child = spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); console.log('ready'); setInterval(() => {}, 1000)"], { stdio: ["ignore", "pipe", "ignore"] });
process.on("SIGTERM", () => process.exit(0));
// Served once the child holds on past SIGTERM, so a stop never finds it unready.
child.stdout.once("data", () =>
	createServer((req, res) => res.end(String(child.pid))).listen(Number(process.env.PORT), "127.0.0.1"),
);
`;
		await writeFile(join(dir, "main.mjs"), holding);
		const port = await freePort();
		const started = await launch({
			command: process.execPath,
			args: ["main.mjs"],
			cwd: dir,
			env: { ...baseEnv(), PORT: String(port) },
			port,
			group: true,
			stopGraceMs: 300,
		});
		if (started.kind !== "running") throw new Error("not started");
		const child = Number(await (await fetch(`${started.baseUrl}/child`)).text());
		expect(alive(child)).toBe(true);
		await started.stop();
		// Answered only once the whole group has ended, not when the target alone has.
		expect(alive(child)).toBe(false);
	});

	it("answers a kill only once what the target started has ended too", async () => {
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
		await started.kill();
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

	/** A target that starts a child holding on past SIGTERM, writes its pid to `child`, and then `then`. */
	const leaving = (then: string) => `
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";
const child = spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); console.log('ready'); setInterval(() => {}, 1000)"], { stdio: ["ignore", "pipe", "ignore"] });
child.stdout.once("data", () => {
	writeFileSync("child", String(child.pid));
	${then}
});
`;
	/** Launches `source` as a group, and the pid of the child it wrote, once the launch has answered. */
	const launching = async (source: string, timeoutMs: number) => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-group-"));
		await writeFile(join(dir, "main.mjs"), source);
		const port = await freePort();
		const answered = await launch(
			{
				command: process.execPath,
				args: ["main.mjs"],
				cwd: dir,
				env: { ...baseEnv(), PORT: String(port) },
				port,
				group: true,
				stopGraceMs: 300,
			},
			timeoutMs,
		).then(
			(started) => ({ started }),
			(error: unknown) => ({ error }),
		);
		const child = Number(await readFile(join(dir, "child"), "utf8"));
		return { answered, child };
	};

	it("ends what the target started before answering that it refused, though the target ended first", async () => {
		const { answered, child } = await launching(leaving("process.exit(1);"), 30_000);
		try {
			expect(answered).toMatchObject({ started: { kind: "refused" } });
			expect(alive(child)).toBe(false);
		} finally {
			if (alive(child)) process.kill(child, "SIGKILL");
		}
	});

	it("ends what the target started before throwing that it did not answer in time", async () => {
		const { answered, child } = await launching(leaving("setInterval(() => {}, 1000);"), 1500);
		try {
			expect(answered).toMatchObject({ error: expect.any(Error) });
			expect(alive(child)).toBe(false);
		} finally {
			if (alive(child)) process.kill(child, "SIGKILL");
		}
	});

	it("ends a stop and a kill once only zombies are left of the group, its processes all ended", async () => {
		// The target's child leaves the group and never reaps its own child, which stays in it a zombie.
		const reaping = `
import { spawn } from "node:child_process";
import { createServer } from "node:http";
const perl = spawn("perl", ["-e", '$| = 1; my $c = fork(); if (!$c) { exit 0 } setpgrp(0, 0); print "$$ $c\\n"; sleep 30'], { stdio: ["ignore", "pipe", "ignore"] });
process.on("SIGTERM", () => process.exit(0));
perl.stdout.once("data", (pids) =>
	createServer((req, res) => res.end(String(pids).trim())).listen(Number(process.env.PORT), "127.0.0.1"),
);
`;
		for (const end of ["stop", "kill"] as const) {
			const dir = await mkdtemp(join(tmpdir(), "conformance-group-"));
			await writeFile(join(dir, "main.mjs"), reaping);
			const port = await freePort();
			const started = await launch({
				command: process.execPath,
				args: ["main.mjs"],
				cwd: dir,
				env: { ...baseEnv(), PORT: String(port) },
				port,
				group: true,
				stopGraceMs: 300,
				killWithinMs: 300,
			});
			if (started.kind !== "running" || !started.kill) throw new Error("not started as a group");
			const [holder = 0] = (await (await fetch(started.baseUrl)).text()).split(" ").map(Number);
			try {
				// Ended in time, or it throws that the group did not end.
				await (end === "stop" ? started.stop() : started.kill());
			} finally {
				process.kill(holder, "SIGKILL");
			}
		}
	});
});
