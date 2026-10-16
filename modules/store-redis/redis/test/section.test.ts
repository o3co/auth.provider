import { createServer } from "node:net";
import { assemble, BootRefused, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import redisModule from "../src/module.ts";

/** A port nothing listens on. */
const closedPort = () =>
	new Promise<number>((resolve) => {
		const server = createServer();
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			server.close(() => resolve(typeof address === "object" && address ? address.port : 0));
		});
	});

/** Boots the module alone, keeping every warning with its fields. */
async function refusalOf(redis: unknown) {
	const recorded = recordingLog();
	const refused = await assemble({
		modules: [redisModule],
		config: { ...kernelConfig(), redis },
		runtime: quietRuntime({
			clock: { now: () => 0 },
			random: { bytes: (n) => new Uint8Array(n) },
			log: recorded.log,
		}),
	}).catch((error) => error);
	return { refused, warned: recorded.lines() };
}

it("refuses boot on a URL that is not redis or rediss, and on a prefix of other characters", async () => {
	const refused: Record<string, unknown> = {
		"another scheme": { url: "http://127.0.0.1:6379" },
		"no URL": { url: "not a url" },
		"an upper-case prefix": { url: "redis://127.0.0.1:6379", prefix: "Store" },
		"a prefix with a colon": { url: "redis://127.0.0.1:6379", prefix: "a:b" },
		"a prefix with a brace": { url: "redis://127.0.0.1:6379", prefix: "a{b" },
		"an empty prefix": { url: "redis://127.0.0.1:6379", prefix: "" },
	};
	for (const [name, redis] of Object.entries(refused)) {
		expect((await refusalOf(redis)).refused, name).toBeInstanceOf(BootRefused);
	}
});

it("refuses boot without telling the URL's password, in the refusal or in a warning", async () => {
	const url = `redis://user:s3cr3t-pass@127.0.0.1:${await closedPort()}`;
	const { refused, warned } = await refusalOf({ url, "connect-timeout-ms": 100 });
	expect(refused).toBeInstanceOf(BootRefused);
	expect(JSON.stringify(refused.refusals)).not.toContain("s3cr3t");
	expect(String(refused)).not.toContain("s3cr3t");
	expect(JSON.stringify(warned)).not.toContain("s3cr3t");
});
