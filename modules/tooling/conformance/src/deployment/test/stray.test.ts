import { spawn } from "node:child_process";
import { mkdtemp, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { startOf } from "../../processes.ts";
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
		await writeFile(
			join(dir, `999999-${pid}`),
			JSON.stringify({ owner: null, group: startOf(pid) }),
		);
		const kept = spawn("sh", ["-c", "sleep 60 & wait"], { detached: true, stdio: "ignore" });
		await markInstance(kept.pid as number, dir);
		expect(await sweepStrayInstances(dir)).toEqual([]);
		await until(() => !alive(pid));
		expect(alive(pid)).toBe(false);
		expect(alive(kept.pid as number)).toBe(true);
		expect(await readdir(dir)).toEqual([`${process.pid}-${kept.pid}`]);
		process.kill(-(kept.pid as number), "SIGKILL");
	});

	it("leaves alone, and names, a group whose leader it cannot hold to the one it marked", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-instances-"));
		const other = spawn("sh", ["-c", "sleep 60 & wait"], { detached: true, stdio: "ignore" });
		const pid = other.pid as number;
		try {
			// The pid taken again by a process started later than the one marked, then a mark that tells no start.
			for (const marked of [
				{ owner: null, group: "Thu Jan  1 00:00:00 1970" },
				{ owner: null, group: null },
				"",
			]) {
				await writeFile(
					join(dir, `999999-${pid}`),
					typeof marked === "string" ? marked : JSON.stringify(marked),
				);
				const named = await sweepStrayInstances(dir);
				expect(named, JSON.stringify(marked)).toEqual([expect.stringContaining(`group ${pid}`)]);
				expect(alive(pid)).toBe(true);
				expect(await readdir(dir)).toEqual([]);
			}
		} finally {
			process.kill(-pid, "SIGKILL");
		}
	});

	it("leaves a mark whose run still runs, telling the run from a later one given its pid", async () => {
		const dir = await mkdtemp(join(tmpdir(), "conformance-instances-"));
		const orphan = spawn("sh", ["-c", "sleep 60 & wait"], { detached: true, stdio: "ignore" });
		const pid = orphan.pid as number;
		// This run's pid, marked as a run that started earlier: that run is gone, its pid taken again.
		await writeFile(
			join(dir, `${process.pid}-${pid}`),
			JSON.stringify({ owner: "Thu Jan  1 00:00:00 1970", group: startOf(pid) }),
		);
		expect(await sweepStrayInstances(dir)).toEqual([]);
		await until(() => !alive(pid));
		expect(alive(pid)).toBe(false);
		expect(await readdir(dir)).toEqual([]);
	});
});
