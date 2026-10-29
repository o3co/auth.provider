import {
	type Assembly,
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { spaces } from "@mod/store";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterEach, describe, expect, it } from "vitest";
import redisModule from "../src/module.ts";
import { fakeRedis } from "./fake-redis.ts";

let app: Assembly | undefined;
afterEach(async () => {
	await app?.stop(1000);
	app = undefined;
});

const replicated = defineModule({ name: "replicated-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "replicated", guarantees: ["replicated"] })),
]);

/** A primary that refuses writes without a replica, as `replicas` needs. */
function primary() {
	const redis = fakeRedis();
	redis.settings["min-replicas-to-write"] = "1";
	redis.settings["min-replicas-max-lag"] = "10";
	return redis;
}

async function boot(port: number, replication?: "replicas" | "none") {
	const recorded = recordingLog();
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	app = await assemble({
		modules: [redisModule, tlsOptionsForTests, asker, ...(replication ? [replicated] : [])],
		config: {
			...kernelConfig(),
			redis: { url: `redis://127.0.0.1:${port}`, ...(replication ? { replication } : {}) },
		},
		runtime: quietRuntime({ clock: { now: () => 0 }, log: recorded.log }),
	});
	const warned = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	return { warned, ready: () => context?.readinessReport(1000).then((r) => r.answer) };
}

const refusal = async (port: number, replication?: "replicas" | "none") => {
	const error = await boot(port, replication).catch((e: unknown) => e);
	expect(error).toBeInstanceOf(BootRefused);
	return (error as BootRefused).refusals.map((r) => r.reason).join("; ");
};

describe("a confirmation round, run once", () => {
	it("refuses boot where the confirming connection reaches another server than the operations", async () => {
		const redis = primary();
		redis.servers.runIds = ["abc", "def"];
		expect(await refusal(await redis.listen(), "replicas")).toMatch(
			/the confirming connection reaches another server than the operations/,
		);
		redis.down();
	});

	it("boots a primary whose two connections reach it alone, as configured", async () => {
		const redis = primary();
		const { ready } = await boot(await redis.listen(), "replicas");
		expect(await ready()).toBe("ready");
		redis.down();
	});

	it("takes a server that changes while the check runs, as in a failover, as no answer, never refusing boot", async () => {
		const redis = primary();
		redis.servers.runIds = ["abc", "def"];
		// The confirming connection's third INFO (after the client's ready check and the command check)
		// is the run id check's: the failover moves both connections just as it is answered.
		redis.servers.onInfo = (connection, count) => {
			if (connection === 1 && count === 3) redis.servers.runIds = ["def", "def"];
		};
		const { ready } = await boot(await redis.listen(), "replicas");
		expect(await ready()).toBe("ready");
		redis.down();
	});

	it("asks it only where replication is declared, as only then is a round run", async () => {
		const redis = primary();
		redis.servers.runIds = ["abc", "def"];
		const { ready } = await boot(await redis.listen());
		expect(await ready()).toBe("ready");
		redis.down();
	});

	it("answers unready once the connections part after boot, and ready once they meet again", async () => {
		const redis = primary();
		const { warned, ready } = await boot(await redis.listen(), "replicas");
		expect(await ready()).toBe("ready");
		redis.servers.runIds = ["abc", "def"];
		expect(await ready()).toBe("unready");
		expect(warned()).toContainEqual([
			"redis.settings_unmet",
			{ problems: expect.stringMatching(/reaches another server/) },
		]);
		redis.servers.runIds = ["abc"];
		expect(await ready()).toBe("ready");
		redis.down();
	});
});

describe("a store script, run once", () => {
	it("refuses boot, naming a store script, where the server cannot run it", async () => {
		const redis = primary();
		redis.storeScripts.fail = true;
		expect(await refusal(await redis.listen())).toMatch(/the server fails a store script/);
		redis.down();
	});

	it("refuses boot, naming batchAcross, where the server runs the read script and not the batch across", async () => {
		const redis = primary();
		redis.storeScripts.failWhere = "local marks = {}";
		expect(await refusal(await redis.listen())).toMatch(
			/the server fails a store script \(batchAcross\)/,
		);
		redis.down();
	});

	it("refuses boot, naming it, where the server splits keys across nodes and refuses a script over two partitions", async () => {
		const redis = primary();
		redis.storeScripts.splitsKeys = true;
		expect(await refusal(await redis.listen())).toMatch(/splits keys across nodes/);
		redis.down();
	});

	it("never names a store script for a passing state of the server: busy with a script, or loading its data", async () => {
		for (const state of [
			"BUSY Redis is busy running a script. You can only call SCRIPT KILL or SHUTDOWN NOSAVE.",
			"LOADING Redis is loading the dataset in memory",
		]) {
			const redis = primary();
			redis.storeScripts.transient = state;
			const reasons = await refusal(await redis.listen());
			expect(reasons, state).not.toMatch(/store script/);
			redis.down();
		}
	});

	it("answers unready once a store script fails after boot", async () => {
		const redis = primary();
		const { ready } = await boot(await redis.listen(), "replicas");
		expect(await ready()).toBe("ready");
		redis.storeScripts.fail = true;
		expect(await ready()).toBe("unready");
		redis.storeScripts.fail = false;
		expect(await ready()).toBe("ready");
		redis.down();
	});
});
