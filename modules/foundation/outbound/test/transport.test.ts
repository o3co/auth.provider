import {
	createServer,
	type IncomingMessage,
	type Server,
	type ServerResponse,
	setGlobalProxyFromEnv,
} from "node:http";
import { createServer as createTlsServer } from "node:https";
import {
	type AddressInfo,
	createServer as createRawServer,
	setDefaultAutoSelectFamily,
} from "node:net";
import { isUnavailable } from "@mod/kernel";
import { policyOf, policySettings } from "@mod/outbound-policy";
import { testTlsOptions } from "@mod/tls-options/testing";
import { configuredUrl } from "@mod/url-setting/testing";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { DestinationRefused, type OutboundUnavailable } from "../src/contract.ts";
import { outboundOver, section } from "../src/module.ts";
import { type Lookup, type Resolver, send } from "../src/transport.ts";
import { authority, destination } from "./fixtures/certificates.ts";

// A connection to `rerouted.from` reaches a local server instead, and is recorded: a private address
// the transport checked is dialed, and nothing is sent anywhere else.
const rerouted = vi.hoisted(() => ({
	from: "",
	to: 0,
	dials: [] as { host: string | undefined; port: number | undefined }[],
}));
vi.mock("node:net", async (original) => {
	const real = await original<typeof import("node:net")>();
	return {
		...real,
		connect: (...args: unknown[]) => {
			const options = args[0] as { host?: unknown; port?: number } | null;
			if (typeof options === "object" && options?.host === rerouted.from) {
				rerouted.dials.push({ host: rerouted.from, port: options.port });
				return real.connect({ host: "127.0.0.1", port: rerouted.to });
			}
			return (real.connect as (...a: unknown[]) => ReturnType<typeof real.connect>)(...args);
		},
	};
});

/** The operator's policy at its plainest, checking the addresses a test's admitted URL reaches. */
/** Every TLS connection's floor, as tls-options' defaults give it. */
const withFloor = { floor: testTlsOptions };
const anyPublic = policyOf(policySettings.parse({ "allow-any-public": true }));

let server: Server;
let port = 0;
/** What the test server saw of a request: its target and the headers it got, by route. */
type Seen = Partial<
	Record<"url" | "host" | "encoding" | "method" | "type" | "body" | "agent", string | undefined>
> & { named?: string[]; all?: IncomingMessage["headers"] };
const seen: Seen[] = [];
let endlessClosed = false;
const routes: Record<string, (req: IncomingMessage, res: ServerResponse) => void> = {
	"/ok": (_req, res) => {
		res.setHeader("set-cookie", ["a=1", "b=2"]);
		res.end("hello");
	},
	"/big": (_req, res) => res.end("x".repeat(2000)),
	"/endless": (_req, res) => {
		const writing = setInterval(() => res.write("x".repeat(1000)), 5);
		res.on("close", () => {
			clearInterval(writing);
			endlessClosed = true;
		});
	},
	"/echo": (req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (chunk: Buffer) => chunks.push(chunk));
		req.on("end", () => {
			Object.assign(seen.at(-1) ?? {}, {
				url: req.url,
				method: req.method,
				type: req.headers["content-type"],
				named: req.rawHeaders.filter((_, i) => i % 2 === 0).map((name) => name.toLowerCase()),
				agent: req.headers["user-agent"],
				all: req.headers,
				body: Buffer.concat(chunks).toString(),
			});
			res.end();
		});
	},
	"/slow": (_req, res) => {
		setTimeout(() => res.end("late"), 500);
	},
	"/moved": (_req, res) => {
		res.writeHead(302, { location: "http://127.0.0.1/ok" });
		res.end();
	},
	"/same": (_req, res) => {
		res.writeHead(304);
		res.end();
	},
	"/zipped": (_req, res) => {
		res.writeHead(200, { "content-encoding": "gzip" });
		res.end("not really");
	},
	"/switch": (req) => {
		req.socket.write(
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n",
		);
	},
	"/hints": (_req, res) => {
		res.writeEarlyHints({ link: "</a>; rel=preload" });
		res.end("final");
	},
	"/status": (req, res) => {
		res.writeHead(Number(new URL(req.url ?? "", "http://x").searchParams.get("code")));
		res.end();
	},
	"/identity": (_req, res) => {
		res.writeHead(200, { "content-encoding": "Identity" });
		res.end("plain");
	},
	"/cut": (_req, res) => {
		res.writeHead(200, { "content-length": "2000" });
		res.write("short");
		setTimeout(() => res.socket?.destroy(), 20);
	},
	"/trickle": (_req, res) => {
		res.writeHead(200);
		res.write("a");
		setTimeout(() => res.end("b"), 500);
	},
	"/tall": (_req, res) => {
		res.writeHead(200, { "x-tall": "y".repeat(20_000) });
		res.end();
	},
};

beforeAll(async () => {
	server = createServer((req, res) => {
		seen.push({ host: req.headers.host, encoding: req.headers["accept-encoding"] });
		const url = new URL(req.url ?? "", "http://x");
		routes[url.pathname]?.(req, res);
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	port = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));

/** A resolver that answers from a table and counts its calls; a name not in it never resolves. */
function table(answers: Record<string, readonly string[]>) {
	const calls: string[] = [];
	const resolve: Lookup = async (host) => {
		calls.push(host);
		const found = answers[host];
		if (!found) return new Promise(() => {});
		return found;
	};
	return { calls, resolve };
}
/** A URL on the test server, by the name `svcResolver` answers. */
const svc = (path: string) => `http://svc.test:${port}${path}`;
const svcResolver = () => table({ "svc.test": ["127.0.0.1"] });
const over = (
	resolve: Lookup,
	settings: Record<string, unknown> = {},
	deadlineOf?: (ms: number) => AbortSignal,
	lookups?: number,
) =>
	outboundOver(
		section.parse({
			"allow-any-public": true,
			"plain-loopback": [`svc.test:${port}`, `127.0.0.1:${port}`],
			...settings,
		}),
		resolve,
		withFloor,
		deadlineOf,
		lookups,
	);
/** Lets pending work run until `done` holds, by turns of the event loop, never by the clock. */
const until = async (done: () => boolean) => {
	for (let turn = 0; turn < 1000 && !done(); turn++)
		await new Promise((next) => setImmediate(next));
	if (!done()) throw new Error("never came");
};
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

describe("outbound", () => {
	it("resolves a name once and connects only to the address it checked", async () => {
		const { calls, resolve } = svcResolver();
		const answer = await over(resolve).fetch(svc("/ok"));
		expect(new TextDecoder().decode(answer.body)).toBe("hello");
		expect(answer.headers.get("set-cookie")).toBe("a=1, b=2");
		expect(calls).toEqual(["svc.test"]);
		expect(seen.at(-1)).toEqual({ host: `svc.test:${port}`, encoding: "identity" });
	});

	it("checks an address written in the URL without resolving it", async () => {
		const { calls, resolve } = table({});
		expect((await over(resolve).fetch(`http://127.0.0.1:${port}/ok`)).status).toBe(200);
		for (const spelled of ["10.0.0.1", "2130706433", "0x7f.1", "[::1]", "[::ffff:a00:1]"]) {
			expect(await failure(over(resolve).fetch(`https://${spelled}/`)), spelled).toBe(
				"special-address",
			);
		}
		expect(calls).toEqual([]);
	});

	it("sends plain http to a plain-loopback pair only where every address it resolves to is loopback", async () => {
		const before = seen.length;
		for (const addresses of [
			["10.0.0.1"],
			["127.0.0.1", "10.0.0.1"],
			["::7f00:1"],
			["::ffff:0:7f00:1"],
		]) {
			const { resolve } = table({ "svc.test": addresses });
			expect(await failure(over(resolve).fetch(svc("/ok"))), addresses.join()).toBe(
				"special-address",
			);
		}
		expect(seen.length).toBe(before);
		for (const addresses of [["127.0.0.1"], ["::ffff:127.0.0.1"]]) {
			const { resolve } = table({ "svc.test": addresses });
			expect((await over(resolve).fetch(svc("/ok"))).status, addresses.join()).toBe(200);
		}
	});

	it("reaches an address written in the URL as written, never the IPv4 it may carry", async () => {
		const { calls, resolve } = table({});
		const before = seen.length;
		for (const spelled of ["[::7f00:1]", "[::ffff:0:7f00:1]"]) {
			expect(await failure(over(resolve).fetch(`http://${spelled}:${port}/ok`)), spelled).toBe(
				"special-address",
			);
		}
		expect(seen.length).toBe(before);
		expect((await over(resolve).fetch(`http://[::ffff:7f00:1]:${port}/ok`)).status).toBe(200);
		expect(calls).toEqual([]);
	});

	it("names the host as the URL writes an address, IPv4 mapped into IPv6 too", async () => {
		const { resolve } = table({});
		const answer = await over(resolve).fetch(`http://[::ffff:7f00:1]:${port}/ok`);
		expect([answer.status, seen.at(-1)?.host]).toEqual([200, `[::ffff:7f00:1]:${port}`]);
	});

	it("refuses a name when any address it resolves to is special, before connecting", async () => {
		const { resolve } = table({ "public.test": ["8.8.8.8", "10.0.0.1"], "inside.test": ["::1"] });
		const before = seen.length;
		expect(await failure(over(resolve).fetch("https://public.test/"))).toBe("special-address");
		expect(await failure(over(resolve).fetch("https://inside.test/"))).toBe("special-address");
		expect(seen.length).toBe(before);
	});

	it("reaches a private address for an internal host the caller names as its operator's, and nowhere else", async () => {
		const { resolve } = table({ "alb.corp": ["10.255.255.1"], "other.corp": ["10.255.255.1"] });
		const out = over(resolve, { "internal-hosts": ["alb.corp"] });
		// Named by the operator's URL at alb.corp: no other origin is reached at a private address.
		const quick = { internal: configuredUrl("https://alb.corp/"), timeoutMs: 100 };
		// Past the address check, the request goes on to connect, where no one answers.
		expect(await failure(out.fetch("https://alb.corp/", {}, quick))).toMatch(
			/^unavailable: (timeout|unreachable)$/,
		);
		expect(await failure(out.fetch("https://alb.corp/", {}, { timeoutMs: 100 }))).toBe(
			"special-address",
		);
		expect(await failure(out.fetch("https://other.corp/", {}, quick))).toBe("special-address");
		// The same host at another port is another service: its private answer is refused.
		expect(await failure(out.fetch("https://alb.corp:8443/", {}, quick))).toBe("special-address");
		expect(
			await failure(out.fetch(`https://127.0.0.1:${port}/ok`, {}, quick)),
			"loopback stays refused",
		).toBe("special-address");
	});

	it("fetches signed material over plain http from the caller's hosts, at public addresses alone", async () => {
		const { resolve } = table({
			"svc.test": ["127.0.0.1"],
			"crl.test": ["10.0.0.1"],
			"lo.test": ["127.0.0.1"],
		});
		const hosts = { hosts: ["svc.test", "crl.test", "lo.test"] };
		const answer = await over(resolve).fetchSigned(svc("/ok"), {}, hosts);
		expect(new TextDecoder().decode(answer.body)).toBe("hello");
		expect(await failure(over(resolve).fetchSigned("http://crl.test/", {}, hosts))).toBe(
			"special-address",
		);
		expect(await failure(over(resolve).fetchSigned("http://lo.test/", {}, hosts))).toBe(
			"special-address",
		);
		expect(await failure(over(resolve).fetchSigned(svc("/moved"), {}, hosts))).toBe("redirect");
		expect(await failure(over(resolve).fetchSigned(svc("/ok"), {}, { hosts: [] }))).toBe(
			"not-allowed",
		);
		expect(await failure(over(resolve).fetch("http://crl.test/"))).toBe("scheme");
	});

	it("caps signed material by its own size, apart from every other answer's", async () => {
		const { resolve } = svcResolver();
		const hosts = { hosts: ["svc.test"] };
		const small = over(resolve, { "max-response-size": "1000B" });
		expect((await small.fetchSigned(svc("/big"), {}, hosts)).body.length).toBe(2000);
		const capped = over(resolve, {
			"max-response-size": "1000000B",
			"signed-max-response-size": "1000B",
		});
		expect(await failure(capped.fetchSigned(svc("/big"), {}, hosts))).toBe(
			"unavailable: too-large",
		);
		expect((await capped.fetch(svc("/big"))).body.length).toBe(2000);
		expect(await failure(small.fetchSigned(svc("/big"), {}, { ...hosts, maxBytes: 1000 }))).toBe(
			"unavailable: too-large",
		);
	});

	it("never follows a redirect, and answers a 304 as it is", async () => {
		const { resolve } = svcResolver();
		expect(await failure(over(resolve).fetch(svc("/moved")))).toBe("redirect");
		// Nor for the operator's own URL: a request reaches no origin but the one admitted.
		const inside = over(resolve, { "internal-hosts": ["svc.test"] });
		const own = { internal: configuredUrl(svc("/moved")) };
		expect(await failure(inside.fetch(svc("/moved"), {}, own))).toBe("redirect");
		expect((await over(resolve).fetch(svc("/same"))).status).toBe(304);
	});

	it("is unavailable past the size, the time or the header cap, or with an encoded body", async () => {
		const { resolve } = svcResolver();
		expect(await failure(over(resolve, { "max-response-size": "1000B" }).fetch(svc("/big")))).toBe(
			"unavailable: too-large",
		);
		expect(await failure(over(resolve).fetch(svc("/big"), {}, { maxBytes: 1000 }))).toBe(
			"unavailable: too-large",
		);
		expect((await over(resolve).fetch(svc("/big"), {}, { maxBytes: 1_000_000 })).body.length).toBe(
			2000,
		);
		// A caller narrows the operator's caps, never widens them.
		const capped = over(resolve, { "max-response-size": "1000B" });
		expect(await failure(capped.fetch(svc("/big"), {}, { maxBytes: 1_000_000 }))).toBe(
			"unavailable: too-large",
		);
		// The deadline asked for, past at once, so no load on the machine moves the answer.
		const asked: number[] = [];
		const passed = (ms: number) => {
			asked.push(ms);
			return AbortSignal.abort();
		};
		const timed = over(resolve, { timeout: "50ms" }, passed);
		expect(await failure(timed.fetch(svc("/slow"), {}, { timeoutMs: 10_000 }))).toBe(
			"unavailable: timeout",
		);
		expect(
			await failure(over(resolve, {}, passed).fetch(svc("/slow"), {}, { timeoutMs: 50 })),
		).toBe("unavailable: timeout");
		expect(asked).toEqual([50, 50]);
		expect(await failure(over(resolve).fetch(svc("/zipped")))).toBe(
			"unavailable: unsupported-answer",
		);
		expect(await failure(over(resolve).fetch(svc("/tall")))).toBe("unavailable: too-large");
		const { resolve: never } = table({});
		expect(await failure(over(never, {}, passed).fetch(svc("/ok")))).toBe("unavailable: timeout");
	});

	it("closes the connection as soon as an answer passes the size cap", async () => {
		const { resolve } = svcResolver();
		endlessClosed = false;
		expect(await failure(over(resolve).fetch(svc("/endless"), {}, { maxBytes: 3000 }))).toBe(
			"unavailable: too-large",
		);
		// Well within the deadline, so only the reader can have closed it.
		await new Promise((done) => setTimeout(done, 200));
		expect(endlessClosed).toBe(true);
	});

	it("takes only positive, finite numbers to narrow by, as the caller's own error", async () => {
		const { resolve } = svcResolver();
		const big = svc("/big");
		for (const bad of [Number.NaN, 0, -1, Number.POSITIVE_INFINITY]) {
			for (const narrower of [{ maxBytes: bad }, { timeoutMs: bad }]) {
				await expect(over(resolve).fetch(big, {}, narrower), String(bad)).rejects.toBeInstanceOf(
					RangeError,
				);
			}
		}
		expect((await over(resolve).fetch(big, {}, { maxBytes: 2000, timeoutMs: 1000 })).status).toBe(
			200,
		);
	});

	it("refuses a request past the number running at once, without waiting", async () => {
		const { resolve } = svcResolver();
		const outbound = over(resolve, { "max-concurrent": 1 });
		// Addresses written in the URL, so no lookup is running: only the requests count.
		// A destination refused before sending takes no place.
		expect(await failure(outbound.fetch("ftp://svc.test/"))).toBe("scheme");
		const first = outbound.fetch(`http://127.0.0.1:${port}/slow`);
		expect(await failure(outbound.fetch(`http://127.0.0.1:${port}/ok`))).toBe("unavailable: busy");
		expect((await first).status).toBe(200);
		expect((await outbound.fetch(svc("/ok"))).status).toBe(200);
	});

	it("gives a request's place back at its deadline, and lets no more names resolve at once than requests may run", async () => {
		let settle: (addresses: readonly string[]) => void = () => {};
		const calls: string[] = [];
		const slow: Lookup = (host) => {
			calls.push(host);
			return new Promise((done) => {
				settle = done;
			});
		};
		// Each request's deadline fires only when the test says, so no load on the machine moves it.
		const deadlines: AbortController[] = [];
		const deadlineOf = () => {
			const deadline = new AbortController();
			deadlines.push(deadline);
			return deadline.signal;
		};
		const other = `http://other.svc.test:${port}/ok`;
		const pairs = [`svc.test:${port}`, `other.svc.test:${port}`, `127.0.0.1:${port}`];
		const outbound = over(slow, { "max-concurrent": 1, "plain-loopback": pairs }, deadlineOf);
		const first = failure(outbound.fetch(svc("/ok")));
		await until(() => calls.length === 1);
		deadlines.at(-1)?.abort();
		expect(await first).toBe("unavailable: timeout");
		// The place is back, so an address written in the URL is reached.
		expect((await outbound.fetch(`http://127.0.0.1:${port}/ok`)).status).toBe(200);
		// The name still resolving holds the only lookup, so another name is refused at once.
		for (let i = 0; i < 3; i++) {
			expect(await failure(outbound.fetch(other))).toBe("unavailable: busy");
		}
		expect(calls).toHaveLength(1);
		settle(["127.0.0.1"]);
		// The settled lookup gives its place back before the loop turns again.
		await new Promise((next) => setImmediate(next));
		// The lookup's place is back: the name is looked up again, and runs past the deadline.
		const again = failure(outbound.fetch(svc("/ok")));
		await until(() => calls.length === 2);
		deadlines.at(-1)?.abort();
		expect(await again).toBe("unavailable: timeout");
	});

	it("sends plain http to a plain-internal pair only where every address is private, checked on each request", async () => {
		let answer: readonly string[] = [];
		const resolve: Lookup = async () => answer;
		const received: { authorization?: string; body: string }[] = [];
		const ledgerServer = createServer((req, res) => {
			const chunks: Buffer[] = [];
			req.on("data", (chunk: Buffer) => chunks.push(chunk));
			req.on("end", () => {
				received.push({
					...(req.headers.authorization ? { authorization: req.headers.authorization } : {}),
					body: Buffer.concat(chunks).toString(),
				});
				res.end("ok");
			});
		});
		await new Promise<void>((ready) => ledgerServer.listen(0, "127.0.0.1", ready));
		Object.assign(rerouted, {
			from: "10.255.255.1",
			to: (ledgerServer.address() as AddressInfo).port,
			dials: [],
		});
		const pair = "ledger.internal:9092";
		const outbound = over(resolve, { "plain-internal": [pair] });
		const ledger = `http://${pair}/verify`;
		const own = { internal: configuredUrl(ledger) };
		for (const [addresses, reason] of [
			[["93.184.216.34"], "plain-public"],
			[["10.1.2.3", "93.184.216.34"], "plain-public"],
			[["93.184.216.34", "10.1.2.3"], "plain-public"],
			[[], "special-address"],
			[["::7f00:1"], "special-address"],
			[["169.254.169.254"], "special-address"],
			[["::ffff:100.100.100.200"], "special-address"],
			[["fd00:ec2::254"], "special-address"],
			[["fe80::1"], "special-address"],
			[["64:ff9b::a01:203"], "special-address"],
		] as const) {
			answer = addresses;
			expect(await failure(outbound.fetch(ledger, {}, own)), addresses.join()).toBe(reason);
		}
		// Private alone: the request, its credential and its body, goes to the checked address itself.
		answer = ["10.255.255.1"];
		const asked = {
			method: "POST",
			credential: "Bearer s3cret",
			body: '{"subject":"alice"}',
		} as const;
		const answered = await outbound.fetch(ledger, asked, own);
		expect([answered.status, rerouted.dials, received]).toEqual([
			200,
			[{ host: "10.255.255.1", port: 9092 }],
			[{ authorization: "Bearer s3cret", body: '{"subject":"alice"}' }],
		]);
		// The next request asks again: a name turned public is refused, with no second connection
		// and no credential sent.
		answer = ["93.184.216.34"];
		expect(await failure(outbound.fetch(ledger, asked, own))).toBe("plain-public");
		expect([rerouted.dials.length, received.length]).toEqual([1, 1]);
		// Without the caller's own URL, or for an outside party's choice, plain http is not taken at all.
		expect(await failure(outbound.fetch(ledger))).toBe("scheme");
		expect(await failure(outbound.fetch(ledger, {}, { ...own, outsideChosen: true }))).toBe(
			"scheme",
		);
		await new Promise((closed) => ledgerServer.close(closed));
	});

	it("answers how many names a caller may resolve at once, the outside party's share apart", () => {
		const shares = (lookups: number) => {
			const out = over(table({}).resolve, { "max-concurrent": 16 }, undefined, lookups);
			return [out.lookupsOf({ outsideChosen: true }), out.lookupsOf({}), out.lookupsOf()];
		};
		expect([shares(1), shares(2), shares(5)]).toEqual([
			[0, 1, 1],
			[1, 1, 1],
			[2, 3, 3],
		]);
	});

	it("refuses a switch of protocols and gives its place back, and waits past an informational answer", async () => {
		const { resolve } = svcResolver();
		const outbound = over(resolve, { "max-concurrent": 1, timeout: "2s" });
		for (let i = 0; i < 2; i++) {
			const started = Date.now();
			expect(await failure(outbound.fetch(svc("/switch")))).toBe("unavailable: unsupported-answer");
			// Node closes it with neither an answer nor an error: refused as it closes, not at the deadline.
			expect(Date.now() - started).toBeLessThan(1000);
		}
		const answer = await outbound.fetch(svc("/hints"));
		expect([answer.status, new TextDecoder().decode(answer.body)]).toEqual([200, "final"]);
	});

	it("sends the method, headers and body it is given", async () => {
		const { resolve } = svcResolver();
		const answer = await over(resolve).fetch(svc("/echo"), {
			method: "POST",
			headers: { "content-type": "text/plain", "Accept-Encoding": "gzip", "User-Agent": "other" },
			body: "payload",
		});
		expect(answer.status).toBe(200);
		// The encoding and the product's name are outbound's own, sent once whatever the caller wrote.
		expect(seen.at(-1)).toMatchObject({
			encoding: "identity",
			agent: "auth-provider",
			method: "POST",
			type: "text/plain",
			body: "payload",
		});
		const named = seen.at(-1)?.named ?? [];
		expect(named.filter((name) => name === "user-agent" || name === "accept-encoding")).toEqual([
			"user-agent",
			"accept-encoding",
		]);
	});

	it("decides the host and how the message is framed and carried, whatever the caller writes", async () => {
		const { resolve } = svcResolver();
		const answer = await over(resolve).fetch(svc("/echo"), {
			method: "POST",
			headers: {
				Host: "denied.test",
				Connection: "upgrade",
				Upgrade: "other",
				"Keep-Alive": "timeout=99",
				TE: "trailers",
				Trailer: "x-late",
				"Transfer-Encoding": "chunked",
				"Content-Length": "999",
				"Proxy-Connection": "keep-alive",
			},
			body: "payload",
		});
		expect(answer.status).toBe(200);
		const all = seen.at(-1)?.all ?? {};
		expect(all.host).toBe(`svc.test:${port}`);
		expect(all["content-length"]).toBe("7");
		for (const name of [
			"upgrade",
			"keep-alive",
			"te",
			"trailer",
			"transfer-encoding",
			"proxy-connection",
		]) {
			expect(all[name], name).toBeUndefined();
		}
		expect(all.connection).not.toBe("upgrade");
		expect(seen.at(-1)?.body).toBe("payload");
	});

	it("refuses every 3xx but 304 as a redirect, and answers any other status as it is", async () => {
		const { resolve } = svcResolver();
		const status = (code: number) => over(resolve).fetch(svc(`/status?code=${code}`));
		for (const code of [300, 307, 399])
			expect(await failure(status(code)), `${code}`).toBe("redirect");
		for (const code of [204, 400, 503]) expect((await status(code)).status).toBe(code);
	});

	it("is unavailable when the body is cut short or comes past the deadline, and takes identity in any case", async () => {
		const { resolve } = svcResolver();
		expect(await failure(over(resolve).fetch(svc("/cut")))).toBe("unavailable: unreachable");
		expect(await failure(over(resolve).fetch(svc("/trickle"), {}, { timeoutMs: 100 }))).toBe(
			"unavailable: timeout",
		);
		expect(new TextDecoder().decode((await over(resolve).fetch(svc("/identity"))).body)).toBe(
			"plain",
		);
	});

	it("is unavailable when a name does not resolve", async () => {
		const failing: Lookup = () => Promise.reject(new Error("not found"));
		expect(await failure(over(failing).fetch(svc("/ok")))).toBe("unavailable: unreachable");
	});

	it("connects to the first checked address, whichever way the connection asks for it", async () => {
		const { resolve } = table({ "svc.test": ["127.0.0.1", "::1"] });
		for (const autoSelect of [true, false]) {
			setDefaultAutoSelectFamily(autoSelect);
			try {
				expect((await over(resolve).fetch(svc("/ok"))).status).toBe(200);
			} finally {
				setDefaultAutoSelectFamily(true);
			}
		}
	});

	it("is unavailable when the resolver throws, at once or later", async () => {
		const admitted = {
			url: new URL("https://svc.test/"),
			host: "svc.test",
			port: 443,
			plain: false,
			loopback: false,
			internal: false,
		};
		const limits = { maxBytes: 1000, timeoutMs: 1000 };
		const atOnce: Resolver = () => {
			throw new Error("resolver");
		};
		expect(await failure(send(admitted, {}, limits, atOnce, anyPublic, undefined, withFloor))).toBe(
			"unavailable: unreachable",
		);
		expect(
			await failure(
				send(
					admitted,
					{},
					limits,
					async () => atOnce("", AbortSignal.timeout(1)),
					anyPublic,
					undefined,
					withFloor,
				),
			),
		).toBe("unavailable: unreachable");
	});

	it("asks with GET for the path and query unless told otherwise", async () => {
		const { resolve } = svcResolver();
		await over(resolve).fetch(svc("/echo?x=1"));
		expect(seen.at(-1)).toMatchObject({ url: "/echo?x=1", method: "GET" });
		expect(seen.at(-1)?.all?.host).toBe(`svc.test:${port}`);
	});

	it("speaks TLS for https, naming the host it checked", async () => {
		const hello: Buffer[] = [];
		const raw = createRawServer((socket) =>
			socket.once("data", (chunk: Buffer) => {
				hello.push(chunk);
				socket.destroy();
			}),
		);
		await new Promise<void>((done) => raw.listen(0, "127.0.0.1", done));
		const at = (raw.address() as AddressInfo).port;
		// Loopback lets 127.0.0.1 pass the address check, so the handshake reaches the raw server.
		const admitted = {
			url: new URL(`https://svc.test:${at}/`),
			host: "svc.test",
			port: at,
			plain: false,
			loopback: true,
			internal: false,
		};
		const limits = { maxBytes: 1000, timeoutMs: 1000 };
		const answer = send(
			admitted,
			{},
			limits,
			async () => ["127.0.0.1"],
			anyPublic,
			undefined,
			withFloor,
		);
		expect(await failure(answer)).toBe("unavailable: unreachable");
		raw.close();
		// A TLS handshake record, naming the host, never plain text.
		expect(hello[0]?.[0]).toBe(0x16);
		expect(hello[0]?.includes("svc.test")).toBe(true);
	});

	it("checks the server's certificate on a direct connection: its name the host checked, by an authority trusted [oidc-discovery-7.1-d]", async () => {
		const tls = createTlsServer(destination, (_req, res) => res.end("{}"));
		await new Promise<void>((done) => tls.listen(0, "127.0.0.1", done));
		const at = (tls.address() as AddressInfo).port;
		// Loopback lets 127.0.0.1 pass the address check, so the handshake reaches the server.
		const toward = (host: string) => ({
			url: new URL(`https://${host}:${at}/`),
			host,
			port: at,
			plain: false,
			loopback: true,
			internal: false,
		});
		const limits = { maxBytes: 1000, timeoutMs: 2000 };
		const reach = (host: string, trust: { ca?: string } = { ca: authority }) =>
			failure(
				send(toward(host), {}, limits, async () => ["127.0.0.1"], anyPublic, undefined, {
					...withFloor,
					...trust,
				}),
			);
		expect(await reach("idp.example.test")).toBe("answered");
		// A certificate for another name, or one no trusted authority issued, ends the connection.
		expect(await reach("other.example.test")).toBe("unavailable: unreachable");
		expect(await reach("idp.example.test", {})).toBe("unavailable: unreachable");
		tls.close();
	});

	it("goes direct even where the process sends requests through a proxy", async () => {
		const proxied: string[] = [];
		const proxy = createServer((req, res) => {
			proxied.push(req.url ?? "");
			res.end("proxy");
		});
		await new Promise<void>((done) => proxy.listen(0, "127.0.0.1", done));
		const via = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
		const restore = setGlobalProxyFromEnv({ HTTP_PROXY: via, HTTPS_PROXY: via });
		const { resolve } = svcResolver();
		try {
			const answer = await over(resolve).fetch(svc("/ok"));
			expect(new TextDecoder().decode(answer.body)).toBe("hello");
		} finally {
			restore();
			proxy.close();
		}
		expect(proxied).toEqual([]);
	});
});
