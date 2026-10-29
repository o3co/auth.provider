import { connect } from "node:net";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { afterEach, beforeAll, expect, it, vi } from "vitest";
import redisModule from "../src/module.ts";

/** A port no test takes: `listen(0)` picks from the ephemeral range, never port 1. */
const refusedPort = 1;

beforeAll(async () => {
	const answer = await new Promise<string>((resolve) => {
		const socket = connect(refusedPort, "127.0.0.1");
		socket.once("connect", () => {
			socket.destroy();
			resolve("connected");
		});
		socket.once("error", (error: NodeJS.ErrnoException) => resolve(error.code ?? "error"));
	});
	if (answer !== "ECONNREFUSED") {
		throw new Error(
			`127.0.0.1:${refusedPort} must refuse connections for these tests (got ${answer})`,
		);
	}
});

/** Boots the module alone, keeping every warning with its fields. */
async function refusalOf(redis: unknown) {
	const recorded = recordingLog();
	const refused = await assemble({
		modules: [redisModule, tlsOptionsForTests],
		config: { ...kernelConfig(), redis },
		runtime: quietRuntime({
			clock: { now: () => 0 },
			random: { bytes: (n) => new Uint8Array(n) },
			log: recorded.log,
		}),
	}).catch((error) => error);
	return { refused, warned: recorded.lines() };
}

it("refuses boot on a URL that is not redis or rediss, a prefix of other characters, a timeout out of bounds or with no unit, or a declaration of another shape, at the key and saying why", async () => {
	const url = "redis://127.0.0.1:6379";
	const prefix = "Invalid string: must match pattern /^[a-z0-9-]+$/";
	const refused: [string, object, string, string][] = [
		["another scheme", { url: "http://127.0.0.1:6379" }, "redis.url", "Invalid URL"],
		["no URL", { url: "not a url" }, "redis.url", "Invalid URL"],
		["an upper-case prefix", { url, prefix: "Store" }, "redis.prefix", prefix],
		["a prefix with a colon", { url, prefix: "a:b" }, "redis.prefix", prefix],
		["a prefix with a brace", { url, prefix: "a{b" }, "redis.prefix", prefix],
		["an empty prefix", { url, prefix: "" }, "redis.prefix", prefix],
		[
			"a connect timeout under 100ms",
			{ url, "connect-timeout": "99ms" },
			"redis.connect-timeout",
			"Too small: expected number to be >=100",
		],
		[
			"a command timeout past a minute",
			{ url, "command-timeout": "61s" },
			"redis.command-timeout",
			"Too big: expected number to be <=60000",
		],
		[
			"a timeout as a bare number",
			{ url, "replication-timeout": 1000 },
			"redis.replication-timeout",
			"written with its unit, such as 30s",
		],
		[
			"a timeout as a string of a number",
			{ url, "command-timeout": "1000" },
			"redis.command-timeout",
			"duration must name its unit",
		],
		[
			"a durability other than none",
			{ url, durability: "fsync" },
			"redis.durability",
			'Invalid input: expected "none"',
		],
		[
			"a declared setting it does not read",
			{ url, "server-settings": { "maxmemory-samples": 5 } },
			"redis.server-settings",
			'Unrecognized key: "maxmemory-samples"',
		],
		[
			"a declared appendfsync Redis has no such value of",
			{ url, "server-settings": { appendfsync: "sometimes" } },
			"redis.server-settings.appendfsync",
			'Invalid option: expected one of "always"|"everysec"|"no"',
		],
	];
	for (const [name, redis, where, reason] of refused) {
		const r = (await refusalOf(redis)).refused;
		expect(r, name).toBeInstanceOf(BootRefused);
		expect((r as BootRefused).refusals, name).toEqual([{ where, reason }]);
	}
});

it("refuses boot at redis.url on a URL with a query, naming where each option is written instead and never a value", async () => {
	const reasons = async (url: string) => {
		const { refused } = await refusalOf({ url });
		expect(refused, url).toBeInstanceOf(BootRefused);
		const { refusals } = refused as BootRefused;
		expect(
			refusals.map((r) => r.where),
			url,
		).toEqual(["redis.url"]);
		return refusals[0]?.reason;
	};
	const lead = "redis.url carries no query: write each option as its own setting: ";
	const tls =
		"tls as rediss:// with the tls-options section, the server's authority in the platform's store";
	expect(await reasons("rediss://127.0.0.1:6379?tls=x")).toBe(`${lead}${tls}`);
	expect(await reasons("rediss://127.0.0.1:6379?tls=RedisCloudFixed")).toBe(`${lead}${tls}`);
	expect(await reasons("redis://127.0.0.1:6379?tls=1")).toBe(`${lead}${tls}`);
	expect(
		await reasons("redis://127.0.0.1:6379?autoResendUnfulfilledCommands=true&family=6&db=2"),
	).toBe(
		`${lead}an option is not taken; family as redis.address-family (ipv4 or ipv6); db as the URL's path (/2)`,
	);
	const secret = await reasons(
		"redis://127.0.0.1:6379?password=s3cr3t-pass&AbCd1234Token&x%3As3cr3t=1",
	);
	expect(secret).toBe(`${lead}password in the URL (user:password@host); an option is not taken`);
	const empty =
		"redis.url carries no query: write each option as its own setting, and take out the ?";
	expect(await reasons("redis://127.0.0.1:6379?")).toBe(empty);
	expect(await reasons("redis://127.0.0.1:6379?&&")).toBe(empty);
});

afterEach(() => vi.unstubAllEnvs());

it("warns at every boot where DEBUG turns on the client's own debug log, with no value", async () => {
	const url = `redis://user:s3cr3t-pass@127.0.0.1:${refusedPort}`;
	const debugWarned = async (debug: string) => {
		vi.stubEnv("DEBUG", debug);
		const { warned } = await refusalOf({ url, "connect-timeout": "100ms" });
		return warned.filter((line) => line.event === "redis.client_debug_log");
	};
	expect(await debugWarned("ioredis:*")).toEqual([
		{ level: "warn", event: "redis.client_debug_log", fields: {} },
	]);
	expect(await debugWarned("express:*")).toEqual([]);
});

it("refuses boot without telling the URL's password, in the refusal or in a warning", async () => {
	const url = `redis://user:s3cr3t-pass@127.0.0.1:${refusedPort}`;
	const { refused, warned } = await refusalOf({ url, "connect-timeout": "100ms" });
	expect(refused).toBeInstanceOf(BootRefused);
	expect(JSON.stringify(refused.refusals)).not.toContain("s3cr3t");
	expect(String(refused)).not.toContain("s3cr3t");
	expect(JSON.stringify(warned)).not.toContain("s3cr3t");
});
