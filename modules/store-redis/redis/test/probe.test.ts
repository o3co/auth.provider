import {
	type Assembly,
	assemble,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { spaces } from "@mod/store";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import type { Redis } from "ioredis";
import { afterEach, describe, expect, it } from "vitest";
import redisModule from "../src/module.ts";
import { redisProbe } from "../src/probe.ts";
import { fakeRedis } from "./fake-redis.ts";

/** Waits until `holds`, checking every 10 ms, for 2 s at most: on the event, not on a guess of its time. */
async function until(holds: () => boolean | Promise<boolean>) {
	for (let tries = 0; tries < 200 && !(await holds()); tries++) {
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

let app: Assembly | undefined;
afterEach(async () => {
	await app?.stop(1000);
	app = undefined;
});

/** A space that must never be evicted, so boot checks the eviction policy. */
const kept = defineModule({ name: "kept-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "kept", guarantees: ["no-eviction"] })),
]);

async function boot(port: number, extra: readonly Module[] = []) {
	const recorded = recordingLog();
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	let now = 0;
	app = await assemble({
		modules: [redisModule, tlsOptionsForTests, asker, ...extra],
		config: { ...kernelConfig(), redis: { url: `redis://127.0.0.1:${port}` } },
		runtime: quietRuntime({
			clock: { now: () => now },
			random: { bytes: (n) => new Uint8Array(n) },
			log: recorded.log,
		}),
	});
	/** The events of the warn lines so far. */
	const warned = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => line.event);
	/** The fields of the warn lines so far. */
	const warnedFields = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => line.fields);
	return {
		warned,
		warnedFields,
		/** A probe past the second a check of the server serves. */
		ready: () => {
			now += 1000;
			return context?.readinessReport(1000).then((r) => r.answer);
		},
	};
}

it("refuses to start where it cannot connect, by the failure's code alone", async () => {
	const redis = fakeRedis();
	const port = await redis.listen();
	redis.down();
	const refused = await assemble({
		modules: [redisModule, tlsOptionsForTests],
		config: { ...kernelConfig(), redis: { url: `redis://127.0.0.1:${port}` } },
		runtime: quietRuntime(),
	}).catch((error: { refusals?: unknown }) => error.refusals);
	expect(refused).toEqual([
		{
			where: "redis.url",
			reason: "cannot connect to Redis, or cannot check its configuration (ECONNREFUSED)",
		},
	]);
});

describe("the redis probe", () => {
	it("passes when both connections answer PING", async () => {
		const redis = fakeRedis();
		const { ready } = await boot(await redis.listen());
		redis.pinged.clear();
		expect(await ready()).toBe("ready");
		expect(redis.pinged.size).toBe(2);
		redis.down();
	});

	it("answers unready once the server no longer gives what boot checked, and ready again when it does", async () => {
		const redis = fakeRedis();
		const { warned, ready } = await boot(await redis.listen(), [kept]);
		expect(await ready()).toBe("ready");
		redis.settings.role = "slave";
		expect(await ready()).toBe("unready");
		redis.settings.role = "master";
		expect(await ready()).toBe("ready");
		redis.settings["maxmemory-policy"] = "allkeys-lru";
		expect(await ready()).toBe("unready");
		expect(warned()).toContain("redis.settings_unmet");
		redis.settings["maxmemory-policy"] = "noeviction";
		expect(await ready()).toBe("ready");
		redis.down();
	});

	it("answers unready once the server splits keys across nodes, as boot would refuse", async () => {
		const redis = fakeRedis();
		const { warned, ready } = await boot(await redis.listen());
		expect(await ready()).toBe("ready");
		redis.storeScripts.splitsKeys = true;
		expect(await ready()).toBe("unready");
		expect(warned()).toContain("redis.settings_unmet");
		redis.storeScripts.splitsKeys = false;
		expect(await ready()).toBe("ready");
		redis.down();
	});

	it("fails once the server is gone", async () => {
		const redis = fakeRedis();
		const { ready } = await boot(await redis.listen());
		redis.down();
		await until(async () => (await ready()) === "unready");
		expect(await ready()).toBe("unready");
	});

	it("logs an error event instead of letting it end the process, and then answers unready", async () => {
		const redis = fakeRedis();
		const { warned, warnedFields, ready } = await boot(await redis.listen());
		redis.stray();
		await until(() => warned().includes("redis.error"));
		expect(warned()).toContain("redis.error");
		// By a code alone, never the message, which may name the host.
		for (const fields of warnedFields()) {
			expect(fields).toEqual({ code: expect.stringMatching(/^([A-Z][A-Za-z0-9_]+|unknown)$/) });
		}
		redis.down();
		await until(async () => (await ready()) === "unready");
		expect(await ready()).toBe("unready");
	});
});

describe("the redis probe's check of what boot checked", () => {
	/** The probe over two connections and a check a test scripts, on a clock it moves. */
	function probing(answer: () => Promise<readonly string[]> = async () => []) {
		const recorded = recordingLog();
		const clock = { at: 1_000_000, now: () => clock.at };
		const counts = { pings: 0, checks: 0 };
		const connection = {
			ping: async () => {
				counts.pings++;
				if (connections.down) throw new Error("Connection is closed.");
				return "PONG";
			},
		} as unknown as Redis;
		const connections = { down: false };
		const unmet = () => {
			counts.checks++;
			return answer();
		};
		const probe = redisProbe([connection, connection], unmet, recorded.log, clock);
		return {
			clock,
			counts,
			connections,
			run: () => probe.check(new AbortController().signal),
			warned: () => recorded.lines().filter((line) => line.level === "warn"),
		};
	}

	it("starts at most once a second from its start, while every run PINGs both connections", async () => {
		const p = probing();
		await p.run();
		p.clock.at += 999;
		await p.run();
		expect(p.counts).toEqual({ pings: 4, checks: 1 });
		p.clock.at += 1;
		await p.run();
		expect(p.counts).toEqual({ pings: 6, checks: 2 });
	});

	it("reads a failed answer within the second as it reads a passed one, warning once, and checks again after it", async () => {
		let problems = ["the server changed"];
		const p = probing(async () => problems);
		await expect(p.run()).rejects.toThrow();
		await expect(p.run()).rejects.toThrow();
		expect(p.counts.checks).toBe(1);
		expect(p.warned().map((line) => line.event)).toEqual(["redis.settings_unmet"]);
		problems = [];
		await expect(p.run()).rejects.toThrow();
		p.clock.at += 1000;
		await expect(p.run()).resolves.toBeUndefined();
		expect(p.counts.checks).toBe(2);
	});

	it("reads a check that threw within the second too", async () => {
		const p = probing(() => Promise.reject(new Error("timed out")));
		await expect(p.run()).rejects.toThrow("timed out");
		await expect(p.run()).rejects.toThrow("timed out");
		expect(p.counts.checks).toBe(1);
		p.clock.at += 1000;
		await expect(p.run()).rejects.toThrow("timed out");
		expect(p.counts.checks).toBe(2);
	});

	it("joins a check still running, also past the second, never starting a second one", async () => {
		const running = Promise.withResolvers<readonly string[]>();
		const p = probing(() => running.promise);
		const runs = [p.run()];
		await until(() => p.counts.checks === 1);
		p.clock.at += 5000;
		runs.push(p.run());
		await until(() => p.counts.pings === 4);
		await new Promise((resolve) => setTimeout(resolve, 10));
		expect(p.counts.checks).toBe(1);
		running.resolve([]);
		await Promise.all(runs);
		expect(p.counts.checks).toBe(1);
		await p.run();
		expect(p.counts.checks).toBe(2);
	});

	it("checks anew where the clock was set back", async () => {
		const p = probing();
		await p.run();
		p.clock.at -= 1;
		await p.run();
		expect(p.counts.checks).toBe(2);
	});

	it("fails at once on a dropped connection within the second, starting no check", async () => {
		const p = probing();
		await p.run();
		p.connections.down = true;
		await expect(p.run()).rejects.toThrow("Connection is closed.");
		p.clock.at += 1000;
		await expect(p.run()).rejects.toThrow("Connection is closed.");
		expect(p.counts.checks).toBe(1);
	});
});
