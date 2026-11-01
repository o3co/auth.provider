import { execFileSync, spawn } from "node:child_process";
import { describe, expect, it } from "vitest";
import { groupLive, startOf } from "../src/processes.ts";

/** The process's state and group, as `ps` prints them. */
const seen = (pid: number) => {
	try {
		return execFileSync("ps", ["-o", "stat=,pgid=", "-p", String(pid)], {
			encoding: "utf8",
		}).trim();
	} catch {
		return "";
	}
};
const until = async (done: () => boolean) => {
	for (let i = 0; i < 50 && !done(); i++) await new Promise((r) => setTimeout(r, 100));
};

describe("a process as this host tells it", () => {
	it("starts at one time, told the same each time asked, and none where no process runs", () => {
		const now = startOf(process.pid);
		expect(now).toEqual(expect.any(String));
		expect(startOf(process.pid)).toBe(now);
		expect(startOf(999_999)).toBeUndefined();
	});

	it("is a live group while one of its processes is no zombie, and none once only zombies are left", async () => {
		const live = spawn("sh", ["-c", "sleep 60 & wait"], { detached: true, stdio: "ignore" });
		// A child leading a group of its own exits; its parent, outside the group, never reaps it.
		const parent = spawn(
			"perl",
			["-e", '$| = 1; my $p = fork(); if (!$p) { setpgrp(0, 0); exit 0 } print "$p\\n"; sleep 30'],
			{ stdio: ["ignore", "pipe", "ignore"] },
		);
		try {
			const zombie = Number(
				await new Promise<string>((resolve) =>
					parent.stdout.once("data", (d) => resolve(String(d))),
				),
			);
			await until(() => new RegExp(`^Z\\S*\\s+${zombie}$`).test(seen(zombie)));
			expect(seen(zombie)).toMatch(new RegExp(`^Z\\S*\\s+${zombie}$`));
			expect(groupLive(zombie)).toBe(false);
			expect(groupLive(live.pid as number)).toBe(true);
			expect(groupLive(999_999)).toBe(false);
		} finally {
			parent.kill("SIGKILL");
			process.kill(-(live.pid as number), "SIGKILL");
		}
	});
});
