import { connect } from "node:net";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { tlsOptionsForTests } from "@mod/tls-options/testing";
import { beforeAll, expect, it } from "vitest";
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

it("refuses boot on a URL that is not redis or rediss, a prefix of other characters, a timeout out of bounds or with no unit, or a declaration of another shape", async () => {
	const refused: Record<string, unknown> = {
		"another scheme": { url: "http://127.0.0.1:6379" },
		"no URL": { url: "not a url" },
		"an upper-case prefix": { url: "redis://127.0.0.1:6379", prefix: "Store" },
		"a prefix with a colon": { url: "redis://127.0.0.1:6379", prefix: "a:b" },
		"a prefix with a brace": { url: "redis://127.0.0.1:6379", prefix: "a{b" },
		"an empty prefix": { url: "redis://127.0.0.1:6379", prefix: "" },
		"a connect timeout under 100ms": { url: "redis://127.0.0.1:6379", "connect-timeout": "99ms" },
		"a command timeout past a minute": { url: "redis://127.0.0.1:6379", "command-timeout": "61s" },
		"a timeout as a bare number": { url: "redis://127.0.0.1:6379", "replication-timeout": 1000 },
		"a timeout as a string of a number": {
			url: "redis://127.0.0.1:6379",
			"command-timeout": "1000",
		},
		"a durability other than none": { url: "redis://127.0.0.1:6379", durability: "fsync" },
		"a declared setting it does not read": {
			url: "redis://127.0.0.1:6379",
			"server-settings": { "maxmemory-samples": 5 },
		},
		"a declared appendfsync Redis has no such value of": {
			url: "redis://127.0.0.1:6379",
			"server-settings": { appendfsync: "sometimes" },
		},
	};
	for (const [name, redis] of Object.entries(refused)) {
		expect((await refusalOf(redis)).refused, name).toBeInstanceOf(BootRefused);
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
		`${lead}autoResendUnfulfilledCommands is not taken; family as redis.address-family (ipv4 or ipv6); db as the URL's path (/2)`,
	);
	const secret = await reasons("redis://127.0.0.1:6379?password=s3cr3t-pass&x%3As3cr3t=1");
	expect(secret).toBe(`${lead}password in the URL (user:password@host); an option is not taken`);
});

it("refuses boot without telling the URL's password, in the refusal or in a warning", async () => {
	const url = `redis://user:s3cr3t-pass@127.0.0.1:${refusedPort}`;
	const { refused, warned } = await refusalOf({ url, "connect-timeout": "100ms" });
	expect(refused).toBeInstanceOf(BootRefused);
	expect(JSON.stringify(refused.refusals)).not.toContain("s3cr3t");
	expect(String(refused)).not.toContain("s3cr3t");
	expect(JSON.stringify(warned)).not.toContain("s3cr3t");
});
