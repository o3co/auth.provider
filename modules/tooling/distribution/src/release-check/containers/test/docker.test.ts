import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DockerFailed, docker } from "../docker.ts";

/** Puts a `docker` client running `script` alone on the PATH. */
const client = (script: string) => {
	const dir = mkdtempSync(join(tmpdir(), "docker-client-"));
	const file = join(dir, "docker");
	writeFileSync(file, `#!/bin/sh\n${script}\n`);
	chmodSync(file, 0o755);
	vi.stubEnv("PATH", `${dir}:/usr/bin:/bin`);
};
/** Whether a process of that id still runs. */
const alive = (pid: number) => {
	try {
		process.kill(pid, 0);
		return true;
	} catch {
		return false;
	}
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
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(alive(pid)).toBe(false);
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
		await new Promise((resolve) => setTimeout(resolve, 100));
		expect(alive(Number(readFileSync(started, "utf8")))).toBe(false);
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
