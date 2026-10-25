import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Command } from "../../commands/commands.ts";
import { reclaimOrphans } from "../orphans.ts";

/** A command that answers as `answer` says, keeping each call; one it does not know answers nothing. */
function commands(
	answer: (cmd: string, args: readonly string[]) => Promise<string> | string = () => "",
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
		return { stdout: await answer(cmd, args) };
	};
	return { command, calls };
}

describe("the suites a run left behind", () => {
	it("takes down the suites whose owner is gone, keeping their logs, and leaves a live owner's", async () => {
		const logs = await mkdtemp(join(tmpdir(), "reclaimed-"));
		const { command, calls } = commands((_cmd, args) => {
			if (args[0] === "ps")
				return [
					"a1\t111\to3co-oidf-live\tlive-server-1",
					"b1\t222\to3co-oidf-gone\tgone-server-1",
					"b2\t222\to3co-oidf-gone\tgone-mongodb-1",
				].join("\n");
			if (args[0] === "logs") return `log of ${args.at(-1)}`;
			if (args[0] === "network" && args[1] === "ls") return "n1";
			return "";
		});
		const reclaimed = await reclaimOrphans(command, logs, (pid) => pid === 111);
		expect(reclaimed).toEqual(["o3co-oidf-gone"]);
		const removed = calls.filter((c) => c.args[0] === "rm").flatMap((c) => c.args);
		expect(removed).toEqual(expect.arrayContaining(["b1", "b2"]));
		expect(removed).not.toContain("a1");
		expect(calls.some((c) => c.args.join(" ") === "network rm n1")).toBe(true);
		expect((await readdir(logs)).sort()).toEqual([
			"o3co-oidf-gone-gone-mongodb-1.log",
			"o3co-oidf-gone-gone-server-1.log",
		]);
		expect(await readFile(join(logs, "o3co-oidf-gone-gone-server-1.log"), "utf8")).toBe(
			"log of b1",
		);
		for (const c of calls) expect(c.timeoutMs).toBeGreaterThan(0);
	});
});
