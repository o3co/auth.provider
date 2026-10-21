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
import * as scripts from "../src/scripts.ts";
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

	it("refuse boot where the server refuses EVAL, or a command a script calls, naming it in either Redis's words", async () => {
		const evalRefused = primary();
		evalRefused.refused.add("EVAL");
		expect(await refusal(await evalRefused.listen())).toMatch(/the server refuses EVAL\b/);
		evalRefused.down();
		for (const wording of ["7.0", "7.4"] as const) {
			const inScript = primary();
			inScript.scripts.refused = ["HSET", "PEXPIRETIME"];
			inScript.scripts.wording = wording;
			const reasons = await refusal(await inScript.listen());
			expect(reasons, wording).toMatch(/the server refuses HSET\b/);
			expect(reasons, wording).toMatch(/the server refuses PEXPIRETIME\b/);
			inScript.down();
		}
	});

	it("tell a refused key from a refused command, naming the store's keys", async () => {
		const redis = primary();
		redis.scripts.keysRefused = true;
		const reasons = await refusal(await redis.listen());
		expect(reasons).toContain("the server refuses this user the store's keys");
		expect(reasons).not.toMatch(/refuses EVAL/);
		redis.down();
		for (const wording of ["7.0", "7.4"] as const) {
			const inScript = primary();
			inScript.scripts.keysRefusedIn = ["HSET"];
			inScript.scripts.wording = wording;
			const said = await refusal(await inScript.listen());
			expect(said, wording).toContain("the server refuses this user the store's keys");
			expect(said, wording).not.toMatch(/refuses HSET/);
			inScript.down();
		}
	});

	it("take a write refused for want of replicas as no answer, never as a refused command", async () => {
		const redis = primary();
		redis.writes.noReplicas = true;
		const { ready } = await boot(await redis.listen(), "replicas");
		expect(await ready()).toBe("ready");
		redis.down();
	});

	it("send SET of the confirmation key where replication is declared, and WAIT only with replicas", async () => {
		const outcome = async (refused: string, replication?: "none" | "replicas") => {
			const redis = primary();
			redis.refused.add(refused);
			const answer = await boot(await redis.listen(), replication).then(
				() => "booted",
				(error: unknown) => (error as BootRefused).refusals.map((r) => r.reason).join("; "),
			);
			await app?.stop(1000);
			app = undefined;
			redis.down();
			return answer;
		};
		expect(await outcome("SET")).toBe("booted");
		expect(await outcome("WAIT")).toBe("booted");
		expect(await outcome("SET", "none")).toMatch(/the server refuses SET\b/);
		expect(await outcome("WAIT", "none")).toBe("booted");
		expect(await outcome("SET", "replicas")).toMatch(/the server refuses SET\b/);
		expect(await outcome("WAIT", "replicas")).toMatch(/the server refuses WAIT\b/);
	});

	it("cover every command the store's scripts call", () => {
		const { commands, ...others } = scripts;
		const covered = new Set([...commands.matchAll(/'([A-Z]+)'/g)].map((m) => m[1]));
		for (const [name, text] of Object.entries(others)) {
			for (const called of String(text).matchAll(/redis\.call\('([A-Z]+)'/g)) {
				expect(covered.has(called[1]), `${name}: ${called[1]}`).toBe(true);
			}
		}
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
