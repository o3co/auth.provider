import { type ChildProcess, spawn } from "node:child_process";
import { docker as dockerRun, dockerSync, dockerWithin } from "@mod/docker-client";
import { afterAll, beforeAll, expect, it } from "vitest";
import { freePort } from "./checks.ts";
import { configured, installed } from "./full-app.ts";

const image = "redis:7.4-alpine";
let container = "";
let redisUrl = "";
let app: ChildProcess | undefined;

async function waitFor(what: string, check: () => boolean | Promise<boolean>, ms = 30_000) {
	const end = Date.now() + ms;
	while (Date.now() < end) {
		if (await check()) return;
		await new Promise((r) => setTimeout(r, 200));
	}
	throw new Error(`${what} did not happen in ${ms} ms`);
}

const docker = (...args: string[]) => dockerSync(args, dockerWithin.control);
const run = (...args: string[]) => dockerRun(["run", ...args], dockerWithin.run);
/** Whether Redis answers PING; a container still starting answers nothing yet. */
const pings = () => {
	try {
		return docker("exec", container, "redis-cli", "ping").includes("PONG");
	} catch {
		return false;
	}
};

beforeAll(async () => {
	const port = await freePort();
	// What the redis module's boot checks ask of the server for the spaces full declares.
	container = await run(
		"-d",
		"--rm",
		"-p",
		`127.0.0.1:${port}:6379`,
		image,
		"redis-server",
		"--appendonly",
		"yes",
		"--appendfsync",
		"always",
		"--maxmemory-policy",
		"noeviction",
	);
	redisUrl = `redis://127.0.0.1:${port}`;
	await waitFor("redis start", pings);
}, dockerWithin.run + 60_000);

afterAll(() => {
	app?.kill("SIGKILL");
	if (container) docker("rm", "-f", "-v", container);
});

const answers = async (url: string) => {
	try {
		return (await fetch(url)).status;
	} catch {
		return 0;
	}
};

it("boots on the test configuration against a Redis, answers liveness and readiness, and stops on SIGTERM", async () => {
	const target = await installed();
	// With a reachable Redis the composition boots as a multi deployment.
	const port = await freePort();
	await configured(target, { deployment: "multi", redisUrl, port });
	let output = "";
	const child = spawn(process.execPath, ["src/main.ts"], {
		cwd: target,
		env: { APP_CONFIG: "config/local.conf,config/application.conf" },
	});
	app = child;
	child.stdout.on("data", (chunk) => {
		output += chunk;
	});
	child.stderr.on("data", (chunk) => {
		output += chunk;
	});
	const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
		child.once("exit", (code, signal) => resolve({ code, signal })),
	);
	const origin = `http://127.0.0.1:${port}`;
	await waitFor(
		"the app answering",
		async () => {
			if (child.exitCode !== null) throw new Error(`the app exited:\n${output}`);
			return (await answers(`${origin}/_healthcheck`)) === 200;
		},
		60_000,
	);
	expect(await answers(`${origin}/_healthcheck`), output).toBe(200);
	expect(await answers(`${origin}/readyz`), output).toBe(200);

	child.kill("SIGTERM");
	const end = await Promise.race([
		exited,
		new Promise<undefined>((r) => setTimeout(() => r(undefined), 20_000)),
	]);
	// It ends itself after stop; the default handling would end it by the signal instead.
	expect(end, output).toBeDefined();
	expect(end?.signal, output).toBeNull();
	expect(end?.code, output).toBe(0);
	expect(output).not.toContain("kernel.stop_failed");
}, 120_000);
