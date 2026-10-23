import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { setDefaultAutoSelectFamily } from "node:net";
import { isUnavailable } from "@mod/kernel";
import { configuredUrl } from "@mod/url-setting/testing";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { DestinationRefused, type OutboundUnavailable } from "../src/contract.ts";
import { outboundOver, section } from "../src/module.ts";
import { type Lookup, systemLookup } from "../src/transport.ts";

// A name ECS Service Connect answers, as its hosts file lines give it: 127.255.0.1, which its proxy
// takes, and 2600:f0f0::1, which in the environment reported does not reach. A connection to
// 127.255.0.1 reaches the local server instead, and every connection made is recorded.
const dialed = vi.hoisted(() => ({ to: 0, at: [] as string[] }));
vi.mock("node:net", async (original) => {
	const real = await original<typeof import("node:net")>();
	return {
		...real,
		connect: (...args: unknown[]) => {
			const options = args[0] as { host?: string; port?: number } | null;
			if (typeof options === "object" && options !== null) {
				dialed.at.push(String(options.host));
				if (options.host === "127.255.0.1")
					return real.connect({ host: "127.0.0.1", port: dialed.to });
				// An address answered whose connection fails at once: a port nothing listens on.
				if (options.host === "127.255.0.2") return real.connect({ host: "127.0.0.1", port: 1 });
			}
			return (real.connect as (...a: unknown[]) => ReturnType<typeof real.connect>)(...args);
		},
	};
});

const pair = "api-internal:9092";
const url = `http://${pair}/verify`;
const own = { internal: configuredUrl(url) };

/** A resolver answering by family as the hosts file does, recording each lookup. */
function serviceConnect(answers: { all?: readonly string[]; ipv4?: readonly string[] } = {}) {
	const asked: { host: string; family: 4 | undefined }[] = [];
	const resolve: Lookup = async (host, family) => {
		asked.push({ host, family });
		return family === 4
			? (answers.ipv4 ?? ["127.255.0.1"])
			: (answers.all ?? ["2600:f0f0::1", "127.255.0.1"]);
	};
	return { asked, resolve };
}

/** Outbound over the resolver given; `lookups` at once, as the threadpool would allow. */
const over = (resolve: Lookup, settings: Record<string, unknown> = {}, lookups?: number) =>
	outboundOver(
		section.parse({
			"allow-any-public": true,
			"plain-internal": [pair],
			"plain-ipv4": [pair],
			...settings,
		}),
		resolve,
		{},
		AbortSignal.timeout,
		lookups,
	);

const failure = (run: Promise<unknown>) =>
	run.then(
		() => "answered",
		(error) =>
			DestinationRefused.is(error)
				? error.reason
				: isUnavailable(error)
					? `unavailable: ${(error as Partial<OutboundUnavailable>).failure}`
					: error,
	);

let server: Server;
beforeAll(async () => {
	server = createServer((_req, res) => res.end("ok"));
	await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
	dialed.to = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));
afterEach(() => {
	dialed.at.length = 0;
});

describe("plain http to a pair plain-ipv4 names", () => {
	it("resolves its name to IPv4 alone, and reaches the IPv4 address checked", async () => {
		const { asked, resolve } = serviceConnect();
		const answered = await over(resolve).fetch(url, {}, own);
		expect([answered.status, asked, dialed.at]).toEqual([
			200,
			[{ host: "api-internal", family: 4 }],
			["127.255.0.1"],
		]);
	});

	it("is refused as before where the pair is not named in plain-ipv4: the IPv6 answer is public", async () => {
		const { asked, resolve } = serviceConnect();
		expect(await failure(over(resolve, { "plain-ipv4": [] }).fetch(url, {}, own))).toBe(
			"plain-public",
		);
		expect([asked, dialed.at]).toEqual([[{ host: "api-internal", family: undefined }], []]);
	});

	it("checks every IPv4 answer before connecting: a public, metadata or denied one among them refuses, in any order", async () => {
		for (const [ipv4, settings, reason] of [
			[["127.255.0.1", "93.184.216.34"], {}, "plain-public"],
			[["93.184.216.34", "127.255.0.1"], {}, "plain-public"],
			[["169.254.169.254", "127.255.0.1"], {}, "special-address"],
			[["127.255.0.1", "169.254.169.254"], {}, "special-address"],
			[["10.1.2.3", "127.255.0.1"], { deny: ["10.1.2.3"] }, "denied"],
			[[], {}, "special-address"],
		] as const) {
			const { resolve } = serviceConnect({ ipv4 });
			expect(await failure(over(resolve, settings).fetch(url, {}, own)), ipv4.join()).toBe(reason);
		}
		expect(dialed.at).toEqual([]);
	});

	it("says unreachable where the lookup fails, as before, telling it from an empty answer", async () => {
		const failing: Lookup = async () => {
			throw Object.assign(new Error("no IPv4"), { code: "ENOTFOUND" });
		};
		expect(await failure(over(failing).fetch(url, {}, own))).toBe("unavailable: unreachable");
	});

	it("neither resolves again nor falls back to IPv6 where the connection to the address checked fails", async () => {
		const { asked, resolve } = serviceConnect({ ipv4: ["127.255.0.2"] });
		expect(await failure(over(resolve).fetch(url, {}, own))).toBe("unavailable: unreachable");
		expect(asked).toEqual([{ host: "api-internal", family: 4 }]);
		expect(dialed.at).toEqual(["127.255.0.2"]);
	});

	it("tries no second IPv4 answer where the connection to the first fails, though the second would answer", async () => {
		const { asked, resolve } = serviceConnect({ ipv4: ["127.255.0.2", "127.255.0.1"] });
		expect(await failure(over(resolve).fetch(url, {}, own))).toBe("unavailable: unreachable");
		expect([asked.length, dialed.at]).toEqual([1, ["127.255.0.2"]]);
	});

	it("reaches the address checked whether node races address families or not", async () => {
		for (const race of [true, false]) {
			setDefaultAutoSelectFamily(race);
			dialed.at.length = 0;
			const { resolve } = serviceConnect();
			expect((await over(resolve).fetch(url, {}, own)).status, String(race)).toBe(200);
			expect(dialed.at, String(race)).toEqual(["127.255.0.1"]);
		}
		setDefaultAutoSelectFamily(true);
	});

	it("resolves signed material taken as the pair's for IPv4 alone too", async () => {
		const { asked, resolve } = serviceConnect();
		const answered = await over(resolve).fetchSigned(url, {}, { hosts: ["api-internal"], ...own });
		expect([answered.status, asked, dialed.at]).toEqual([
			200,
			[{ host: "api-internal", family: 4 }],
			["127.255.0.1"],
		]);
	});

	it("leaves another port of the name as before", async () => {
		const { asked, resolve } = serviceConnect({ all: ["127.255.0.1"] });
		const other = "http://api-internal:9093/verify";
		const outbound = over(resolve, { "plain-internal": [pair, "api-internal:9093"] });
		expect((await outbound.fetch(other, {}, { internal: configuredUrl(other) })).status).toBe(200);
		expect(asked).toEqual([{ host: "api-internal", family: undefined }]);
	});

	it("resolves the same name at once for IPv4 alone and for every family, neither taking the other's answer", async () => {
		const settle: Record<string, (addresses: readonly string[]) => void> = {};
		const asked: (4 | undefined)[] = [];
		const resolve: Lookup = (_host, family) => {
			asked.push(family);
			return new Promise((done) => {
				settle[String(family)] = done;
			});
		};
		const other = "http://api-internal:9093/verify";
		// Four lookups at once, two of them the deployment's own: both names resolve together.
		const outbound = over(resolve, { "plain-internal": [pair, "api-internal:9093"] }, 4);
		const ipv4 = failure(outbound.fetch(url, {}, own));
		const every = failure(outbound.fetch(other, {}, { internal: configuredUrl(other) }));
		await vi.waitFor(() => expect(asked.sort()).toEqual([4, undefined]));
		settle.undefined?.(["2600:f0f0::1", "127.255.0.1"]);
		settle["4"]?.(["127.255.0.1"]);
		expect([await ipv4, await every]).toEqual(["answered", "plain-public"]);
	});
});

describe("the system's resolver", () => {
	it("answers IPv4 addresses alone where asked for them, the hosts file included", async () => {
		const every = await systemLookup("localhost");
		const ipv4 = await systemLookup("localhost", 4);
		expect(ipv4.length).toBeGreaterThan(0);
		expect(ipv4.every((address) => /^\d+\.\d+\.\d+\.\d+$/.test(address))).toBe(true);
		expect(every.length).toBeGreaterThanOrEqual(ipv4.length);
	});
});

describe("plain-ipv4 in the operator's section", () => {
	const refusal = (settings: Record<string, unknown>) => {
		const parsed = section.safeParse(settings);
		return parsed.success
			? "taken"
			: parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`).join("; ");
	};

	it("takes pairs of either plain list, as the lists compare hosts: case and a trailing dot", () => {
		expect(
			refusal({ "plain-internal": ["api-internal:9092"], "plain-ipv4": ["API-Internal.:9092"] }),
		).toBe("taken");
		expect(refusal({ "plain-loopback": ["sidecar:8080"], "plain-ipv4": ["sidecar:8080"] })).toBe(
			"taken",
		);
	});

	it("refuses a pair neither plain list names, or another port of one, saying so without the pair", () => {
		const said = refusal({
			"plain-internal": ["api-internal:9092"],
			"plain-ipv4": ["api-internal:9093"],
		});
		expect(said).toBe(
			"plain-ipv4: plain-ipv4 names only pairs plain-loopback or plain-internal names",
		);
		expect(said).not.toContain("9093");
	});

	it("refuses a pair whose host is an address, in any spelling a URL reads as one", () => {
		for (const host of [
			"127.255.0.1",
			"127.1",
			"2147483649",
			"0x7f000001",
			"[::ffff:127.0.0.1]",
			"[2600:f0f0::1]",
		]) {
			const pair = `${host}:9092`;
			const said = refusal({ "plain-internal": [pair], "plain-ipv4": [pair] });
			expect(said, host).toContain(
				"plain-ipv4: plain-ipv4 names hosts by name: an address is reached as written, never resolved",
			);
			expect(said, host).not.toContain(host);
		}
	});

	it("refuses a pair named twice, in any spelling the lists take as one", () => {
		const twice = refusal({
			"plain-internal": ["api-internal:9092"],
			"plain-ipv4": ["api-internal:9092", "API-INTERNAL.:9092"],
		});
		expect(twice).toBe("plain-ipv4: plain-ipv4 names a pair once");
	});

	it("refuses an entry that is not a host:port pair, or holds another part of a URL in its host", () => {
		for (const entry of [
			"api-internal",
			"api-internal:09092",
			"api-internal:70000",
			"api internal:9092",
			"api-internal/ignored:9092",
			"user@api-internal:9092",
			"api-internal?x:9092",
			"api-internal#x:9092",
			"api-internal\\x:9092",
			"api-internal:80:9092",
		]) {
			expect(refusal({ "plain-ipv4": [entry] }), entry).toContain("not a host:port pair");
		}
	});

	it("is empty unless set, and nothing then resolves otherwise", () => {
		expect(section.parse({})["plain-ipv4"]).toEqual([]);
	});
});
