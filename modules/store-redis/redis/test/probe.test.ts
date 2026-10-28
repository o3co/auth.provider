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
import { afterEach, describe, expect, it } from "vitest";
import redisModule from "../src/module.ts";
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
	app = await assemble({
		modules: [redisModule, asker, ...extra],
		config: { ...kernelConfig(), redis: { url: `redis://127.0.0.1:${port}` } },
		runtime: quietRuntime({
			clock: { now: () => 0 },
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
		ready: () => context?.readinessReport(1000).then((r) => r.answer),
	};
}

it("refuses to start where it cannot connect, by the failure's code alone", async () => {
	const redis = fakeRedis();
	const port = await redis.listen();
	redis.down();
	const refused = await assemble({
		modules: [redisModule],
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
