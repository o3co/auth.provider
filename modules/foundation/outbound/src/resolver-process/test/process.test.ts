import { execFileSync, spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolverPool } from "../contract.ts";
import { startHelper } from "../process.ts";

const alive = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
};
const until = async (done: () => boolean, ms = 5_000) => {
	const end = Date.now() + ms;
	while (!done() && Date.now() < end) await new Promise((r) => setTimeout(r, 25));
	return done();
};

/** The environment a process was started with, as the OS keeps it. */
const environmentOf = (pid: number) => {
	try {
		return readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").join("\n");
	} catch {
		return execFileSync("ps", ["-wwwE", "-p", String(pid), "-o", "command="], { encoding: "utf8" });
	}
};

describe("the helper, as a process", () => {
	it("answers as the system's lookup answers, in its order, and for IPv4 alone", async () => {
		const pool = resolverPool({ pool: "own", size: 2, warn: () => {}, now: () => Date.now() });
		await pool.start();
		try {
			const system = (await lookup("localhost", { all: true, verbatim: true })).map(
				(a) => a.address,
			);
			expect(await pool.run("localhost")?.answer).toEqual(system);
			const v4 = (await lookup("localhost", { all: true, verbatim: true, family: 4 })).map(
				(a) => a.address,
			);
			expect(await pool.run("localhost", 4)?.answer).toEqual(v4);
		} finally {
			await pool.stop();
		}
	}, 30_000);

	it("is ended by a stop, which waits until it is gone", async () => {
		let pid: number | undefined;
		const pool = resolverPool({
			pool: "own",
			size: 1,
			warn: () => {},
			now: () => Date.now(),
			start: (gen, threads) => {
				const started = startHelper(gen, threads);
				pid = started.pid;
				return started;
			},
		});
		await pool.start();
		expect(pid !== undefined && alive(pid)).toBe(true);
		await pool.stop();
		expect(await until(() => !alive(pid as number))).toBe(true);
	}, 30_000);

	it("gets none of its parent's environment but the resolver's variables and its threads", async () => {
		process.env.OUTBOUND_TEST_SECRET = "s3cr3t-value";
		process.env.LOCALDOMAIN = "example.test";
		const helper = startHelper(1, 3);
		let ready = false;
		helper.on("message", (message) => {
			if ((message as { ready?: boolean }).ready === true) ready = true;
		});
		try {
			// Read once it says it is ready: before its exec, the OS keeps no environment of its own for it.
			expect(await until(() => ready)).toBe(true);
			const env = environmentOf(helper.pid as number);
			expect(env).not.toContain("s3cr3t-value");
			expect(env).not.toContain("NODE_OPTIONS");
			expect(env).toContain("UV_THREADPOOL_SIZE=3");
			expect(env).toContain("LOCALDOMAIN=example.test");
		} finally {
			helper.kill();
			delete process.env.OUTBOUND_TEST_SECRET;
			delete process.env.LOCALDOMAIN;
		}
	});

	it("lets a process that only starts and stops it end, the stop settled", () => {
		const said = execFileSync(
			process.execPath,
			[
				"--input-type=module",
				"-e",
				`import { resolverPool } from ${JSON.stringify(join(import.meta.dirname, "..", "pool.ts"))};
const pool = resolverPool({ pool: "own", size: 1, warn: () => {}, now: () => Date.now() });
await pool.start();
await pool.stop();
process.stdout.write("stopped\\n");`,
			],
			{ encoding: "utf8", timeout: 20_000 },
		);
		expect(said).toBe("stopped\n");
	}, 30_000);

	it("refuses the first start where the helper is never ready, the process kept until it is refused", () => {
		// A helper that never says it is ready, in a process with nothing else open: the start must
		// still be refused, never cut short by the process ending first.
		const said = execFileSync(
			process.execPath,
			[
				"--input-type=module",
				"-e",
				`import { fork } from "node:child_process";
import { poolLimits, resolverPool } from ${JSON.stringify(join(import.meta.dirname, "..", "contract.ts"))};
poolLimits.readyMs = 300;
const silent = ["-e", "process.on('message', () => {}); setInterval(() => {}, 1000)"];
const pool = resolverPool({
	pool: "own", size: 1, warn: () => {}, now: () => Date.now(),
	start: () => {
		const c = fork("--", [], { execArgv: silent, stdio: ["ignore", "ignore", "inherit", "ipc"] });
		return {
			get pid() { return c.pid; },
			send: () => {},
			kill: () => c.kill("SIGKILL"),
			hold: (held) => { if (held) { c.ref(); c.channel?.ref(); } else { c.unref(); c.channel?.unref(); } },
			on: (event, listener) => c.on(event, listener),
		};
	},
});
await pool.start().then(() => process.stdout.write("started\\n"), () => process.stdout.write("refused\\n"));`,
			],
			{ encoding: "utf8", timeout: 20_000 },
		);
		expect(said).toBe("refused\n");
	}, 30_000);

	it("ends itself when its parent is killed", async () => {
		// A parent of its own, started as a deployment starts outbound, printing its helper's pid.
		const parent = spawn(
			process.execPath,
			[
				"--input-type=module",
				"-e",
				`import { startHelper } from ${JSON.stringify(join(import.meta.dirname, "..", "process.ts"))};
const h = startHelper(1, 1);
h.hold(true);
h.on("message", () => process.stdout.write(String(h.pid) + "\\n"));`,
			],
			{ stdio: ["ignore", "pipe", "inherit"] },
		);
		const pid = await new Promise<number>((resolve) =>
			parent.stdout.once("data", (chunk: Buffer) => resolve(Number(chunk.toString().trim()))),
		);
		expect(alive(pid)).toBe(true);
		parent.kill("SIGKILL");
		expect(await until(() => !alive(pid))).toBe(true);
	}, 30_000);
});
