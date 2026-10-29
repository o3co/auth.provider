import { describe, expect, it } from "vitest";
import { DockerFailed } from "../../containers/docker.ts";
import { pidsCurrent } from "../cgroup.ts";

const reading =
	(files: Readonly<Record<string, string>>) =>
	async (path: string): Promise<string> => {
		const content = files[path];
		if (content !== undefined) return content;
		throw new DockerFailed(
			"failed",
			"exec",
			"docker exec failed (1)",
			`cat: can't open '${path}': No such file or directory\n`,
			1,
		);
	};

describe("the processes a container's cgroup counts", () => {
	it("are cgroup v2's count, at the cgroup's root", async () => {
		expect(await pidsCurrent(reading({ "/sys/fs/cgroup/pids.current": "7\n" }))).toBe(7);
	});

	it("are v1's, under its pids controller, where v2's file is not there", async () => {
		expect(await pidsCurrent(reading({ "/sys/fs/cgroup/pids/pids.current": "9\n" }))).toBe(9);
	});

	it("name both places where neither file is there", async () => {
		await expect(pidsCurrent(reading({}))).rejects.toThrow(
			/\/sys\/fs\/cgroup\/pids\.current.*\/sys\/fs\/cgroup\/pids\/pids\.current/,
		);
	});

	it("are not looked for elsewhere where Docker fails or times out: that failure is thrown", async () => {
		for (const kind of ["timeout", "failed", "unstarted", "absent"] as const) {
			let asked = 0;
			const failing = async () => {
				asked += 1;
				throw new DockerFailed(
					kind,
					"exec",
					`docker exec: ${kind}`,
					kind === "failed" ? "Error response from daemon: container is not running" : "",
				);
			};
			await expect(pidsCurrent(failing)).rejects.toMatchObject({ kind });
			expect(asked).toBe(1);
		}
	});
});
