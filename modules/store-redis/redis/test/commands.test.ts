import {
	type Assembly,
	assemble,
	BootRefused,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
	type Module,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { spaces } from "@mod/store";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
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
const replicated = defineModule({ name: "replicated-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "replicated", guarantees: ["replicated"] })),
]);

/** A space whose writes must survive a crash, so the server's fsyncs are checked. */
const durable = defineModule({ name: "durable-owner", replicaSafe: true, takes: [] }, (m) => [
	m.contribute(spaces).by(() => ({ name: "durable", guarantees: ["durable"] })),
]);

/** A primary that refuses writes without a replica, as `replicas` needs. */
function primary() {
	const redis = fakeRedis();
	redis.settings["min-replicas-to-write"] = "1";
	redis.settings["min-replicas-max-lag"] = "10";
	redis.replication.connected = 1;
	return redis;
}

async function boot(
	port: number,
	replication?: "replicas" | "none",
	prefix?: string,
	extra: Module[] = [],
	declared?: Readonly<Record<string, string>>,
) {
	const recorded = recordingLog();
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", replicaSafe: false, takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	const url = `redis://:s3cret@127.0.0.1:${port}`;
	let now = 0;
	app = await assemble({
		modules: [
			redisModule,
			tlsOptionsForTests,
			asker,
			...(replication ? [replicated] : []),
			...extra,
		],
		config: {
			...kernelConfig(),
			redis: {
				url,
				...(replication ? { replication } : {}),
				...(prefix ? { prefix } : {}),
				...(declared ? { "server-settings": declared } : {}),
			},
		},
		runtime: quietRuntime({
			clock: { now: () => now },
			random: { bytes: (n) => new Uint8Array(n) },
			log: recorded.log,
		}),
	});
	const warned = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	return {
		warned,
		/** A probe past the second a check of the server serves. */
		ready: () => {
			now += 1000;
			return context?.readinessReport(1000).then((r) => r.answer);
		},
	};
}

/** Why boot was refused, at `redis`; the refusal never names the URL or its password. */
async function refusal(
	port: number,
	replication?: "replicas" | "none",
	prefix?: string,
): Promise<string> {
	const error = await boot(port, replication, prefix).catch((e: unknown) => e);
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

	it("name the keys a user is refused by the key that sets their prefix, never by its value", async () => {
		const redis = primary();
		redis.writes.keysRefused = true;
		redis.scripts.keysRefused = true;
		const reasons = await refusal(await redis.listen(), "replicas", "private-tenant");
		expect(reasons).toContain("the confirmation key (<redis.prefix>:#confirm)");
		expect(reasons).toContain("the store's keys (<redis.prefix>:{…})");
		expect(reasons).not.toContain("private-tenant");
		redis.down();
	});

	it("refuse boot for a durable space where the server skips its fsyncs while it rewrites, and boot where it does not", async () => {
		const redis = primary();
		Object.assign(redis.settings, { appendonly: "yes", appendfsync: "always" });
		redis.settings["no-appendfsync-on-rewrite"] = "yes";
		const port = await redis.listen();
		const error = await boot(port, undefined, undefined, [durable]).catch((e) => e);
		expect(error).toBeInstanceOf(BootRefused);
		expect(String((error as BootRefused).refusals.map((r) => r.reason))).toContain(
			"no-appendfsync-on-rewrite no",
		);
		await app?.stop(1000);
		redis.settings["no-appendfsync-on-rewrite"] = "no";
		await boot(port, undefined, undefined, [durable]);
		redis.down();
	});

	it("take the declared value of a setting CONFIG GET answers empty, warning at boot of each so taken", async () => {
		const redis = primary();
		redis.settings.appendfsync = "always";
		const { warned } = await boot(await redis.listen(), undefined, undefined, [durable], {
			appendonly: "yes",
			"no-appendfsync-on-rewrite": "no",
		});
		expect(warned()).toContainEqual([
			"redis.settings_declared",
			{ settings: "appendonly, no-appendfsync-on-rewrite" },
		]);
		redis.down();
	});

	it("refuse boot where CONFIG GET answers empty and nothing is declared, naming the setting", async () => {
		const redis = primary();
		const port = await redis.listen();
		const error = await boot(port, undefined, undefined, [durable]).catch((e) => e);
		expect(error).toBeInstanceOf(BootRefused);
		const reasons = String((error as BootRefused).refusals.map((r) => r.reason));
		expect(reasons).toContain(
			"the server's CONFIG GET does not show it: declare appendonly in redis.server-settings",
		);
		redis.down();
	});

	it("take a write refused for want of replicas as no answer, never as a refused command", async () => {
		const redis = primary();
		redis.writes.noReplicas = true;
		const { ready } = await boot(await redis.listen(), "replicas");
		// Booted, never refused; unready, as the ledger's entry waits for writes to be taken.
		expect(await ready()).toBe("unready");
		redis.down();
	});

	it("send SET of the confirmation key where replication is declared, and WAIT only with replicas", async () => {
		const outcome = async (refused: string, replication?: "none" | "replicas") => {
			const redis = primary();
			if (replication !== "replicas") redis.replication.connected = 0;
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

	it("refuse boot as a cluster, not as no connection, where a key is answered as a cluster node answers it", async () => {
		for (const answer of [
			"MOVED 1234 10.0.0.2:6379",
			"ASK 1234 10.0.0.2:6379",
			"CLUSTERDOWN Hash slot not served",
		]) {
			const redis = primary();
			redis.cluster.keysAnswer = answer;
			expect(await refusal(await redis.listen(), "replicas"), answer).toBe(
				"redis: Redis cluster, and proxies that split keys across nodes, are not supported",
			);
			redis.down();
		}
	});

	it("name a refused command beside a cluster's answers, losing neither", async () => {
		const redis = primary();
		redis.cluster.keysAnswer = "MOVED 1234 10.0.0.2:6379";
		redis.refused.add("WAIT");
		const reasons = await refusal(await redis.listen(), "replicas");
		expect(reasons).toContain("the server refuses WAIT: allow it");
		expect(reasons).toContain("Redis cluster, and proxies that split keys across nodes");
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
