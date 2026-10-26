import { existsSync } from "node:fs";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Command } from "../../commands/commands.ts";
import { composeOverride } from "../../compose/compose.ts";
import { SuiteStopFailed, startSuite } from "../suite.ts";

const pin = { tag: "release-v1", commit: "c0ffee", python: ["httpx==1"] };
const host = { name: "host.docker.internal", listen: "127.0.0.1" };

/** A command that answers as `answer` says, keeping each call; one it does not know answers nothing. */
function commands(
	answer: (
		cmd: string,
		args: readonly string[],
	) => Promise<string> | string | { stdout: string; stderr: string } = () => "",
) {
	const calls: { cmd: string; args: readonly string[]; timeoutMs: number; signal?: AbortSignal }[] =
		[];
	const command: Command = async (cmd, args, options) => {
		calls.push({
			cmd,
			args,
			timeoutMs: options.timeoutMs,
			...(options.signal ? { signal: options.signal } : {}),
		});
		const said = await answer(cmd, args);
		return typeof said === "string" ? { stdout: said } : said;
	};
	return { command, calls };
}

const isDown = (args: readonly string[]) => args.includes("down");

describe("the suite's start and stop, held to their time and leaving nothing behind", () => {
	it("marks every container with the process that owns it", () => {
		const text = composeOverride(host, 4242);
		for (const service of ["mongodb", "nginx", "server"]) {
			expect(text).toMatch(
				new RegExp(
					`  ${service}:\\n(    .*\\n|      .*\\n)*    labels:\\n      o3co.oidf.owner: "4242"\\n`,
				),
			);
		}
	});

	it("gives up at the plan's deadline on a step that hangs, and still stops what it started", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-start-"));
		const { command, calls } = commands(
			(cmd, args) =>
				new Promise<string>((resolve, reject) => {
					if (cmd === "git" && args[0] === "-C") return resolve(`${pin.commit}\n`);
					if (cmd === "docker" && args.includes("up")) {
						const signal = calls.at(-1)?.signal;
						signal?.addEventListener("abort", () => reject(new Error("aborted")));
						return;
					}
					resolve("");
				}),
		);
		const started = startSuite(pin, join(dir, "suite"), host, join(dir, "suite.log"), {
			command,
			signal: AbortSignal.timeout(200),
		});
		await expect(started).rejects.toThrow();
		// The stop runs past the deadline, by budgets of its own.
		const down = calls.find((c) => c.cmd === "docker" && isDown(c.args));
		expect(down?.signal).toBeUndefined();
		expect(down?.timeoutMs).toBeGreaterThan(0);
	});

	it("says its stop failed, and keeps what stops the suite, where the containers could not be taken down", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-stop-"));
		const suiteDir = join(dir, "suite");
		const { command } = commands((cmd, args) => {
			if (cmd === "git" && args[0] === "-C") return `${pin.commit}\n`;
			// The suite comes up, never answers before the deadline, and the daemon then fails to take it down.
			if (cmd === "docker" && isDown(args)) throw new Error("the daemon did not answer");
			return "";
		});
		const started = startSuite(pin, suiteDir, host, join(dir, "suite.log"), {
			command,
			signal: AbortSignal.timeout(300),
		});
		const error = await started.then(
			() => undefined,
			(e: unknown) => e,
		);
		// Told as the suite's stop failing, for the caller to keep what stops it.
		expect(error).toBeInstanceOf(SuiteStopFailed);
		const told =
			error instanceof AggregateError ? error.errors.map(String).join("\n") : String(error);
		expect(String(error)).toContain(`its compose files stay in ${suiteDir}`);
		expect(told).toContain("the daemon did not answer");
		expect(existsSync(join(suiteDir, "override.yml"))).toBe(true);
	});

	it("keeps what the containers wrote to their stderr in the suite's log, beside their stdout", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-log-"));
		const { command } = commands((cmd, args) => {
			if (cmd === "git" && args[0] === "-C") return `${pin.commit}\n`;
			// The containers fail to come up: the start fails, and its stop keeps the log.
			if (cmd === "docker" && args.includes("up")) throw new Error("server-1 exited");
			if (cmd === "docker" && args.includes("logs"))
				return { stdout: "server-1 | started\n", stderr: "server-1 | OutOfMemoryError\n" };
			return "";
		});
		await expect(
			startSuite(pin, join(dir, "suite"), host, join(dir, "suite.log"), { command }),
		).rejects.toThrow("server-1 exited");
		const log = await readFile(join(dir, "suite.log"), "utf8");
		expect(log).toContain("server-1 | started\n");
		expect(log).toContain("server-1 | OutOfMemoryError\n");
	});

	it("removes what it prepared, and asks nothing of Compose, where it fails before any container was started", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-early-"));
		const suiteDir = join(dir, "suite");
		const { command, calls } = commands((cmd, args) => {
			// The tag names another commit; and the daemon would fail any Compose command.
			if (cmd === "git" && args[0] === "-C") return "deadbeef\n";
			if (cmd === "docker" && args[0] === "compose") throw new Error("the daemon did not answer");
			return "";
		});
		const error = await startSuite(pin, suiteDir, host, join(dir, "suite.log"), { command }).then(
			() => undefined,
			(e: unknown) => e,
		);
		expect(String(error)).toContain("not the pinned");
		expect(error).not.toBeInstanceOf(SuiteStopFailed);
		expect(calls.some((c) => c.cmd === "docker" && c.args[0] === "compose")).toBe(false);
		expect(existsSync(suiteDir)).toBe(false);
	});
});
