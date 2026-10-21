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
import { afterEach, describe, expect, it } from "vitest";
import redisModule from "../src/module.ts";
import { fakeRedis } from "./fake-redis.ts";

let app: Assembly | undefined;
afterEach(async () => {
	await app?.stop(1000);
	app = undefined;
});

/** A space whose writes are confirmed on every replica, so a write takes a confirmation round. */
const replicated = defineModule({ name: "replicated-owner" }, (m) => [
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
	const asker = defineModule({ name: "asker" }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	const url = `redis://:s3cret@127.0.0.1:${port}`;
	app = await assemble({
		modules: [redisModule, asker, ...(replication ? [replicated] : [])],
		config: {
			...kernelConfig(),
			redis: { url, ...(replication ? { replication } : {}) },
		},
		runtime: quietRuntime({
			clock: { now: () => 0 },
			random: { bytes: (n) => new Uint8Array(n) },
			log: recorded.log,
		}),
	});
	const warned = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	return { warned, ready: () => context?.readinessReport(1000).then((r) => r.answer) };
}

/** Why boot was refused, at `redis`; the refusal never names the URL or its password. */
async function refusal(port: number, replication?: "replicas" | "none"): Promise<string> {
	const error = await boot(port, replication).catch((e: unknown) => e);
	expect(error).toBeInstanceOf(BootRefused);
	const reasons = (error as BootRefused).refusals.map((r) => `${r.where}: ${r.reason}`).join("\n");
	expect(reasons).not.toContain("s3cret");
	return reasons;
}

describe("the commands the store needs", () => {
	it("refuse boot where the server refuses one of a confirmation round's, naming it", async () => {
		for (const command of ["WAIT", "ROLE", "SET", "INFO"]) {
			const redis = primary();
			redis.refused.add(command);
			expect(await refusal(await redis.listen(), "replicas"), command).toMatch(
				new RegExp(`redis: .*the server refuses ${command}\\b`),
			);
			redis.down();
		}
	});

	it("refuse boot where the server refuses a script, or what a script calls, naming which", async () => {
		const evalRefused = primary();
		evalRefused.refused.add("EVAL");
		expect(await refusal(await evalRefused.listen())).toMatch(/the server refuses EVAL\b/);
		evalRefused.down();
		const inScript = primary();
		inScript.scripts.refused = true;
		expect(await refusal(await inScript.listen())).toMatch(
			/the server refuses a command a script calls \(TIME, INFO or PEXPIRETIME\)/,
		);
		inScript.down();
	});

	it("check WAIT only where replication is declared, as only then does a round wait", async () => {
		const redis = primary();
		redis.refused.add("WAIT");
		const { ready } = await boot(await redis.listen());
		expect(await ready()).toBe("ready");
		redis.down();
	});

	it("answer unready once the server refuses one after boot, naming it, and ready once it allows it again", async () => {
		const redis = primary();
		const { warned, ready } = await boot(await redis.listen(), "replicas");
		expect(await ready()).toBe("ready");
		redis.refused.add("WAIT");
		expect(await ready()).toBe("unready");
		expect(warned()).toContainEqual([
			"redis.settings_unmet",
			{ problems: expect.stringMatching(/the server refuses WAIT\b/) },
		]);
		redis.refused.delete("WAIT");
		expect(await ready()).toBe("ready");
		redis.down();
	});
});
