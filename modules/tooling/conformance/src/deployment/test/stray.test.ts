import { spawn } from "node:child_process";
import { mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { markInstance, sweepStrayInstances } from "../stray.ts";

const alive = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
};
const until = async (done: () => boolean) => {
	for (let i = 0; i < 50 && !done(); i++) await new Promise((r) => setTimeout(r, 100));
};

describe("instances a run left behind", () => {
	it("are ended, their whole group, where the run that started them runs no more", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-instances-"));
		const orphan = spawn("sh", ["-c", "sleep 60 & wait"], { detached: true, stdio: "ignore" });
		const pid = orphan.pid as number;
		// A run whose process is gone: no process has this id.
		await writeFile(join(dir, `999999-${pid}`), "");
		const kept = spawn("sh", ["-c", "sleep 60 & wait"], { detached: true, stdio: "ignore" });
		await markInstance(kept.pid as number, dir);
		await sweepStrayInstances(dir);
		await until(() => !alive(pid));
		expect(alive(pid)).toBe(false);
		expect(alive(kept.pid as number)).toBe(true);
		expect(await readdir(dir)).toEqual([`${process.pid}-${kept.pid}`]);
		process.kill(-(kept.pid as number), "SIGKILL");
	});
});
