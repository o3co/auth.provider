import { mkdtemp, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Command } from "../../commands/commands.ts";
import { reclaimOrphans } from "../orphans.ts";

/** A command that answers as `answer` says (its stdout, or both streams), keeping each call; one it does not know answers nothing. */
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
			if (args[0] === "logs") return { stdout: `log of ${args.at(-1)}`, stderr: "" };
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

	const gone = (args: readonly string[]) => {
		if (args[0] === "ps") return "b1\t222\to3co-oidf-gone\tgone-server-1";
		if (args[0] === "logs") return { stdout: "started\n", stderr: "java.lang.OutOfMemoryError\n" };
		if (args[0] === "network" && args[1] === "ls") return "n1";
		return "";
	};

	it("keeps what each container wrote to its stderr, beside its stdout", async () => {
		const logs = await mkdtemp(join(tmpdir(), "reclaimed-"));
		const { command } = commands((_cmd, args) => gone(args));
		await reclaimOrphans(command, logs, () => false);
		const log = await readFile(join(logs, "o3co-oidf-gone-gone-server-1.log"), "utf8");
		expect(log).toContain("started\n");
		expect(log).toContain("java.lang.OutOfMemoryError\n");
	});

	it("takes the suite down though its logs' directory cannot be made, and then tells it", async () => {
		const parent = await mkdtemp(join(tmpdir(), "reclaimed-"));
		// A file where the directory's parent should be: the directory cannot be made.
		await writeFile(join(parent, "full"), "");
		const { command, calls } = commands((_cmd, args) => gone(args));
		await expect(
			reclaimOrphans(command, join(parent, "full", "reclaimed"), () => false),
		).rejects.toThrow("could not be taken down");
		expect(calls.some((c) => c.args[0] === "rm" && c.args.includes("b1"))).toBe(true);
		expect(calls.some((c) => c.args.join(" ") === "network rm n1")).toBe(true);
	});
});
