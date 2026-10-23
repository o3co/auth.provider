import { describe, expect, it } from "vitest";
import { gone, noSuchContainer, pidsCurrent, within } from "../container.ts";

describe("the processes a container's cgroup counts", () => {
	const reading =
		(files: Readonly<Record<string, string>>) =>
		(path: string): string => {
			const content = files[path];
			if (content === undefined)
				throw new Error(`cat: can't open '${path}': No such file or directory`);
			return content;
		};

	it("reads cgroup v2's count, at the cgroup's root", () => {
		expect(pidsCurrent(reading({ "/sys/fs/cgroup/pids.current": "7\n" }))).toBe(7);
	});

	it("reads cgroup v1's, under its pids controller, where v2's is not there", () => {
		expect(pidsCurrent(reading({ "/sys/fs/cgroup/pids/pids.current": "9\n" }))).toBe(9);
	});

	it("names both places where neither is read", () => {
		expect(() => pidsCurrent(reading({}))).toThrow(
			/\/sys\/fs\/cgroup\/pids\.current.*\/sys\/fs\/cgroup\/pids\/pids\.current/,
		);
	});
});

describe("a container already gone", () => {
	const failed = (stderr: string) =>
		Object.assign(new Error("Command failed: docker stop"), { stderr });

	it("is Docker's answer that no such container is there", () => {
		expect(
			noSuchContainer(failed("Error response from daemon: No such container: simple-web-1\n")),
		).toBe(true);
	});

	it("is `docker inspect`'s answer that no such object is there, as any version writes it", () => {
		expect(noSuchContainer(failed("Error: No such object: simple-web-1\n"))).toBe(true);
		expect(noSuchContainer(failed("error: no such object: simple-web-1\n"))).toBe(true);
	});

	it("is not any other failure: a container still running stays an error", () => {
		expect(
			noSuchContainer(
				failed("Error response from daemon: cannot stop container: permission denied\n"),
			),
		).toBe(false);
		expect(noSuchContainer(new Error("spawn docker ENOENT"))).toBe(false);
		expect(
			noSuchContainer(
				failed("permission denied while trying to connect to the Docker daemon socket\n"),
			),
		).toBe(false);
		expect(
			noSuchContainer(
				failed("Cannot connect to the Docker daemon. Is the docker daemon running?\n"),
			),
		).toBe(false);
		expect(noSuchContainer("No such container")).toBe(false);
	});
});

describe("whether a container is gone", () => {
	const failing = (stderr: string) => () => {
		throw Object.assign(new Error("Command failed: docker inspect"), { stderr });
	};

	it("is not where it is inspected", () => {
		expect(gone(() => "[]")).toBe(false);
	});

	it("is where Docker answers that no such object is there", () => {
		expect(gone(failing("Error: No such object: simple-web-1\n"))).toBe(true);
	});

	it("is not told where the inspection fails otherwise: the failure is thrown", () => {
		expect(() =>
			gone(failing("permission denied while trying to connect to the Docker daemon socket\n")),
		).toThrow("docker inspect");
	});
});

describe("a wait with a deadline", () => {
	it("answers what was waited for, within the deadline", async () => {
		await expect(within(Promise.resolve(0), 1_000, "late")).resolves.toBe(0);
	});

	it("fails, as told, where the wait outlasts it", async () => {
		await expect(within(new Promise(() => {}), 10, "the container did not end")).rejects.toThrow(
			"the container did not end",
		);
	});
});
