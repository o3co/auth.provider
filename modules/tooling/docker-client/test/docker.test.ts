import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DockerFailed, docker, dockerSync } from "../src/contract.ts";

/** Puts a `docker` client running `script` alone on the PATH. */
const client = (script: string) => {
	const dir = mkdtempSync(join(tmpdir(), "docker-client-"));
	const file = join(dir, "docker");
	writeFileSync(file, `#!/bin/sh\n${script}\n`);
	chmodSync(file, 0o755);
	vi.stubEnv("PATH", `${dir}:/usr/bin:/bin`);
};
/** Whether a process of that id still runs: one ended but not yet reaped (a zombie, `Z`) does not. */
const alive = (pid: number) => {
	try {
		process.kill(pid, 0);
		return !execFileSync("ps", ["-o", "stat=", "-p", String(pid)])
			.toString()
			.trim()
			.startsWith("Z");
	} catch {
		return false;
	}
};
/**
 * Whether the process has ended, seen within 5 s: a SIGKILL sent to its group ends it only once the
 * kernel next runs it, and the client is not its parent, so no exit tells when.
 */
const ended = async (pid: number) => {
	for (let waited = 0; waited < 5_000 && alive(pid); waited += 20) {
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
	return !alive(pid);
};
/** Waits until the client has written `file`: a shell starts slowly on a busy machine. */
const written = async (file: string) => {
	for (let waited = 0; waited < 5_000 && !existsSync(file); waited += 20) {
		await new Promise((resolve) => setTimeout(resolve, 20));
	}
};
const failure = (running: Promise<unknown>) =>
	running.then(
		() => undefined,
		(error: unknown) => error,
	);

afterEach(() => {
	vi.unstubAllEnvs();
});

vi.setConfig({ testTimeout: 15_000 });

describe("a docker command", () => {
	it("answers what the client wrote, trimmed", async () => {
		client('echo "  $1 $2  "');
		expect(await docker(["inspect", "rc-1"], 5_000)).toBe("inspect rc-1");
	});

	it("is absent where Docker answers that no such container or object is there", async () => {
		client('echo "Error response from daemon: No such container: $2" >&2; exit 1');
		const failed = await failure(docker(["stop", "rc-1"], 5_000));
		expect(failed).toBeInstanceOf(DockerFailed);
		expect(failed).toMatchObject({ kind: "absent", command: "stop" });
		client('echo "Error: No such object: $2" >&2; exit 1');
		expect(await failure(docker(["inspect", "rc-1"], 5_000))).toMatchObject({ kind: "absent" });
	});

	it("failed, what it told kept, where it fails otherwise: a daemon refusing is no absence", async () => {
		client(
			'echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1',
		);
		expect(await failure(docker(["rm", "-f", "rc-1"], 5_000))).toMatchObject({
			kind: "failed",
			code: 1,
			told: expect.stringContaining("permission denied"),
		});
	});

	it("reads a character whose bytes the client wrote apart, on either stream, whole", async () => {
		client(
			"printf '\\343\\201'; printf '\\343\\201' >&2; sleep 0.3; printf '\\202\\n'; printf '\\202' >&2; exit 1",
		);
		const failed = await failure(docker(["logs", "rc-1"], 5_000));
		expect(failed).toMatchObject({ wrote: "\u3042\n", told: "\u3042" });
	});

	it("keeps the app's output in the message where a merged command fails", async () => {
		client(
			'echo "the app said why"; echo "Error response from daemon: can not get logs" >&2; exit 1',
		);
		const failed = await failure(docker(["logs", "rc-1"], 5_000, { merged: true }));
		expect((failed as Error).message).toContain("the app said why");
		expect((failed as Error).message).toContain("can not get logs");
	});

	it("keeps what a failing client wrote to its output, as well as what it told", async () => {
		client('echo "ERR_PNPM_FETCH_404 no such package"; echo "install failed" >&2; exit 1');
		const failed = await failure(docker(["run", "rc-1"], 5_000));
		expect(failed).toMatchObject({
			kind: "failed",
			wrote: expect.stringContaining("ERR_PNPM_FETCH_404"),
			told: expect.stringContaining("install failed"),
		});
		expect((failed as Error).message).toMatch(
			/ERR_PNPM_FETCH_404[\s\S]*install failed|install failed[\s\S]*ERR_PNPM_FETCH_404/,
		);
	});

	it("timed out where the client outlasts its time, the client killed", async () => {
		client("exec sleep 30");
		const began = performance.now();
		expect(await failure(docker(["exec", "rc-1", "true"], 200))).toMatchObject({
			kind: "timeout",
			message: "docker exec did not answer within 0.2 seconds",
		});
		expect(performance.now() - began).toBeLessThan(5_000);
	});

	it("timed out at its time even where something the client started holds its output open, that too ended", async () => {
		const dir = mkdtempSync(join(tmpdir(), "docker-started-"));
		const started = join(dir, "pid");
		client(`sleep 30 &\necho $! > "${started}"\nexec sleep 30`);
		const began = performance.now();
		expect(await failure(docker(["exec", "rc-1", "true"], 2_000))).toMatchObject({
			kind: "timeout",
		});
		expect(performance.now() - began).toBeLessThan(4_000);
		const pid = Number(readFileSync(started, "utf8"));
		expect(await ended(pid)).toBe(true);
	});

	it("stopped where its work's signal ends it, the client and what it started ended", async () => {
		const dir = mkdtempSync(join(tmpdir(), "docker-started-"));
		const started = join(dir, "pid");
		client(`sleep 30 &\necho $! > "${started}"\nexec sleep 30`);
		const ending = new AbortController();
		const running = failure(docker(["exec", "rc-1", "true"], 60_000, { signal: ending.signal }));
		await written(started);
		ending.abort();
		expect(await running).toMatchObject({ kind: "timeout" });
		expect(await ended(Number(readFileSync(started, "utf8")))).toBe(true);
		const already = new AbortController();
		already.abort();
		expect(await failure(docker(["info"], 5_000, { signal: already.signal }))).toMatchObject({
			kind: "timeout",
		});
	});

	it("unstarted where no client can be started", async () => {
		vi.stubEnv("PATH", mkdtempSync(join(tmpdir(), "no-docker-")));
		expect(await failure(docker(["info"], 5_000))).toMatchObject({ kind: "unstarted" });
	});

	it("timed out at once where no time is left, starting nothing", async () => {
		client("echo started >&2; exit 1");
		expect(await failure(docker(["info"], 0))).toMatchObject({ kind: "timeout" });
	});
});

describe("a docker command given its input", () => {
	it("reads it on its standard input", async () => {
		client("cat");
		expect(await docker(["build", "-q", "-"], 5_000, { input: "FROM alpine\n" })).toBe(
			"FROM alpine",
		);
		expect(dockerSync(["inspect", "-"], 5_000, { input: "a recipe" })).toBe("a recipe");
	});
});

describe("a docker command held until it answers", () => {
	/** What a held command threw, or nothing. */
	const thrown = (run: () => unknown) => {
		try {
			run();
			return undefined;
		} catch (error) {
			return error;
		}
	};

	it("answers what the client wrote, trimmed, as `docker` does", () => {
		client('echo "  $1 $2 $3  "');
		expect(dockerSync(["network", "create", "n-1"], 5_000)).toBe("network create n-1");
	});

	it("fails as `docker` sorts it: absent, failed with what it told and wrote, unstarted", () => {
		client('echo "Error: No such container: rc-1" >&2; exit 1');
		expect(thrown(() => dockerSync(["rm", "-f", "rc-1"], 5_000))).toMatchObject({
			kind: "absent",
			command: "rm",
		});
		client('echo "out" ; echo "daemon refused" >&2; exit 2');
		const failed = thrown(() => dockerSync(["ps"], 5_000));
		expect(failed).toBeInstanceOf(DockerFailed);
		expect(failed).toMatchObject({
			kind: "failed",
			code: 2,
			told: "daemon refused\n",
			wrote: "out\n",
		});
		vi.stubEnv("PATH", mkdtempSync(join(tmpdir(), "no-docker-")));
		expect(thrown(() => dockerSync(["info"], 5_000))).toMatchObject({ kind: "unstarted" });
	});

	it("timed out where the client outlasts its time, the client ended and what it told kept", () => {
		client('echo "waiting" >&2; exec sleep 30');
		const started = performance.now();
		expect(thrown(() => dockerSync(["kill", "-s", "KILL", "n"], 1_500))).toMatchObject({
			kind: "timeout",
			message: "docker kill did not answer within 1.5 seconds",
			told: "waiting\n",
		});
		expect(performance.now() - started).toBeLessThan(5_000);
		expect(thrown(() => dockerSync(["ps"], 0))).toMatchObject({ kind: "timeout" });
	});

	it("takes no command that starts a process of its own, running nothing for it", () => {
		const dir = mkdtempSync(join(tmpdir(), "docker-held-"));
		const ran = join(dir, "ran");
		client(`touch ${ran}`);
		for (const args of [
			["build", "-"],
			["run", "redis"],
			["image", "build", "."],
			["compose", "up"],
		]) {
			expect(() => dockerSync(args, 5_000), args.join(" ")).toThrow(TypeError);
		}
		expect(existsSync(ran)).toBe(false);
		dockerSync(["image", "inspect", "t"], 5_000);
		expect(existsSync(ran)).toBe(true);
	});
});
