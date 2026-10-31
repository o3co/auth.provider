import { createConnection } from "node:net";
import { docker as dockerRun, dockerSync, dockerWithin } from "@mod/docker-client";
import { describe, expect, it } from "vitest";
import { startRedis } from "../src/driver.ts";

const docker = (() => {
	try {
		dockerSync(["version"], dockerWithin.control, { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
})();

/** The names of the containers that exist with the label and value given. */
const containers = (label: string) =>
	dockerSync(
		["ps", "-a", "--filter", `label=${label}`, "--format", "{{.Names}}"],
		dockerWithin.control,
	)
		.split("\n")
		.filter(Boolean);

/** Whether a Redis answers PING at the URL, over a plain TCP connection. */
const answers = (url: string) =>
	new Promise<boolean>((resolve) => {
		const { hostname, port } = new URL(url);
		const socket = createConnection({ host: hostname, port: Number(port) }, () => {
			socket.write("PING\r\n");
		});
		socket.once("data", (data) => {
			resolve(data.toString().startsWith("+PONG"));
			socket.end();
		});
		socket.once("error", () => resolve(false));
	});

// A container can take longer to start than a test is given by default, among many tests at once.
const startsWithin = 60_000;

describe.runIf(docker)("a throwaway Redis", () => {
	it(
		"answers at a port docker chose, and is removed when stopped",
		async () => {
			const redis = await startRedis();
			const stopped = redis.stop;
			let stoppedAlready = false;
			const stop = async () => {
				if (!stoppedAlready) await stopped();
				stoppedAlready = true;
			};
			try {
				const { port } = new URL(redis.url);
				expect(Number(port)).toBeGreaterThan(0);
				expect(await answers(redis.url)).toBe(true);
				// Docker bound the host port itself: the binding names none.
				const [name] = containers(`conformance.owner=${process.pid}`);
				const bindings = dockerSync(
					["inspect", "-f", "{{json .HostConfig.PortBindings}}", name ?? "none"],
					dockerWithin.control,
				);
				expect(JSON.parse(bindings)).toEqual({
					"6379/tcp": [{ HostIp: "127.0.0.1", HostPort: "" }],
				});
				await stop();
				expect(await answers(redis.url)).toBe(false);
				expect(containers(`conformance.owner=${process.pid}`)).toEqual([]);
			} finally {
				await stop();
			}
		},
		startsWithin,
	);

	it(
		"gives two started at once a port each",
		async () => {
			const [one, two] = await Promise.all([startRedis(), startRedis()]);
			try {
				expect(one.url).not.toBe(two.url);
				expect([await answers(one.url), await answers(two.url)]).toEqual([true, true]);
			} finally {
				await Promise.all([one.stop(), two.stop()]);
			}
		},
		startsWithin,
	);

	it(
		"removes, before it starts, one a process no longer running left behind",
		async () => {
			// No process holds this pid: the highest a system gives is far below it.
			const gone = "conformance.owner=2147483646";
			await dockerRun(
				["run", "-d", "--label", gone, "--label", "conformance=redis", "redis:7-alpine"],
				dockerWithin.run,
			);
			expect(containers(gone)).toHaveLength(1);
			const redis = await startRedis();
			await redis.stop();
			expect(containers(gone)).toEqual([]);
		},
		startsWithin,
	);
});
