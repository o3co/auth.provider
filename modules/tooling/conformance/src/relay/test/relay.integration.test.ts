import { randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startRedis } from "../../driver.ts";
import { type Command, type Match, type Reply, startRelay, upstreamOf } from "../relay.ts";
import { ask, encode, rawClient, tricklingServer } from "./client.ts";

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const fresh = () => `k-${randomBytes(4).toString("hex")}`;
const text = (b: Buffer | undefined) => b?.toString();
const bulk = (data: string | null) => ({
	kind: "bulk",
	data: data === null ? null : Buffer.from(data),
});
const ok = { kind: "simple", text: "OK" };
/** Until `seen` holds, checked every few ms, within five seconds. */
const until = async (seen: () => boolean) => {
	for (let i = 0; i < 500 && !seen(); i++) await pause(10);
	if (!seen()) throw new Error("not seen in time");
};
/** A relay that names every connection by what it sends, so a request's arrival shows. */
const signalling = () =>
	startRelay({ upstream: upstreamOf(redis.url), roleOf: () => "operations" });

/** A `SET` of the key, which wrote where Redis answered OK. */
const setOf = (key: string): Match => ({
	request: (c) => c.name === "SET" && text(c.args[0]) === key,
	succeeded: (r) => r.kind === "simple" && r.text === "OK",
});
const sameArgs = (a: Command, b: Command) =>
	a.name === b.name &&
	a.args.length === b.args.length &&
	a.args.every((x, i) => x.equals(b.args[i] ?? Buffer.alloc(0)));

let redis: Awaited<ReturnType<typeof startRedis>>;
let other: Awaited<ReturnType<typeof startRedis>>;
beforeAll(async () => {
	[redis, other] = await Promise.all([startRedis(), startRedis()]);
});
afterAll(async () => {
	await Promise.all([redis?.stop(), other?.stop()]);
});

describe("the fault relay passes traffic on", () => {
	it("as it came, a pipeline in one write included", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const c = await rawClient(relay.url);
		const k = fresh();
		c.write(encode("SET", k, "1"), encode("GET", k), encode("PING"));
		expect(await c.replies(3)).toEqual([ok, bulk("1"), { kind: "simple", text: "PONG" }]);
		c.end();
		await relay.close();
	});

	it("keeps the pairing when requests arrive split at every byte", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const c = await rawClient(relay.url);
		const k = fresh();
		await c.trickle(Buffer.concat([encode("PING"), encode("SET", k, "v"), encode("GET", k)]));
		expect(await c.replies(3)).toEqual([{ kind: "simple", text: "PONG" }, ok, bulk("v")]);
		c.end();
		await relay.close();
	});

	it("keeps the pairing when answers arrive split at every byte, a dropped one among them", async () => {
		const server = await tricklingServer([
			Buffer.from("+PONG\r\n"),
			Buffer.from("+OK\r\n"),
			Buffer.from(":5\r\n"),
		]);
		const relay = await startRelay({ upstream: server.upstream });
		const drop = relay.dropReplyTo(setOf("k"));
		const c = await rawClient(relay.url);
		c.write(encode("PING"), encode("SET", "k", "v"), encode("INCR", "n"));
		const dropped = await drop.first;
		await c.closed;
		expect(c.got()).toEqual([{ kind: "simple", text: "PONG" }]);
		expect(dropped.command.name).toBe("SET");
		expect(dropped.collateral).toEqual([
			{ command: { name: "INCR", args: [Buffer.from("n")] }, answered: false },
		]);
		await relay.close();
		await server.stop();
	});
});

describe("the fault relay's faults", () => {
	it("stalls one way: up keeps requests from Redis, down keeps the answers it computed", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const c = await rawClient(relay.url);
		const [up, down] = [fresh(), fresh()];
		relay.stall("up");
		c.write(encode("SET", up, "1"));
		await pause(200);
		expect(await ask(redis.url, "GET", up)).toEqual(bulk(null));
		relay.resume();
		expect(await c.replies(1)).toEqual([ok]);
		relay.stall("down");
		c.write(encode("SET", down, "1"));
		await pause(200);
		expect(await ask(redis.url, "GET", down)).toEqual(bulk("1"));
		expect(c.got()).toHaveLength(1);
		relay.resume();
		expect(await c.replies(2)).toEqual([ok, ok]);
		c.end();
		await relay.close();
	});

	it("delays answers by the time given", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const c = await rawClient(relay.url);
		relay.delay(300, "down");
		const started = performance.now();
		c.write(encode("PING"));
		await c.replies(1);
		expect(performance.now() - started).toBeGreaterThanOrEqual(290);
		c.end();
		await relay.close();
	});

	it("resets the connections it names; a new one goes through", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const c = await rawClient(relay.url);
		c.write(encode("PING"));
		await c.replies(1);
		relay.reset("all");
		await c.closed;
		const again = await rawClient(relay.url);
		again.write(encode("PING"));
		expect(await again.replies(1)).toEqual([{ kind: "simple", text: "PONG" }]);
		again.end();
		await relay.close();
	});
});

describe("dropping an answer", () => {
	it("drops only a write's successful answer, after Redis ran it, and cuts its connection with what came behind", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const [k, before, after] = [fresh(), fresh(), fresh()];
		const drop = relay.dropReplyTo(setOf(k));
		const c = await rawClient(relay.url);
		c.write(encode("GET", before), encode("SET", k, "1"), encode("INCR", after));
		const dropped = await drop.first;
		await c.closed;
		// The read before it was answered; the write ran; nothing after it reached the client.
		expect(c.got()).toEqual([bulk(null)]);
		expect(dropped.reply).toEqual(ok);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk("1"));
		expect(dropped.collateral.map((x) => x.command.name)).toEqual(["INCR"]);
		await relay.close();
	});

	it("passes on an answer that shows no write, and fails as the fault did not happen", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const k = fresh();
		await ask(redis.url, "SET", k, "first");
		const drop = relay.dropReplyTo(setOf(k));
		const c = await rawClient(relay.url);
		c.write(encode("SET", k, "second", "NX"));
		await expect(drop.first).rejects.toThrow(/no write/);
		expect(await c.replies(1)).toEqual([bulk(null)]);
		c.end();
		await expect(relay.close()).rejects.toThrow(/no write/);
	});

	it("drops the answers to a resend of the write too, until ended", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const k = fresh();
		const drop = relay.dropReplyTo(setOf(k), { resends: sameArgs });
		for (const _ of [1, 2]) {
			const c = await rawClient(relay.url);
			c.write(encode("SET", k, "1"));
			await c.closed;
			expect(c.got()).toEqual([]);
		}
		await drop.first;
		expect(drop.resends).toHaveLength(1);
		drop.end();
		const c = await rawClient(relay.url);
		c.write(encode("SET", k, "1"));
		expect(await c.replies(1)).toEqual([ok]);
		c.end();
		await relay.close();
	});
});

describe("a transaction", () => {
	const cases: [string, string[][]][] = [
		["run", [["MULTI"], ["SET", "K", "1"], ["EXEC"]]],
		["discarded", [["MULTI"], ["SET", "K", "1"], ["DISCARD"]]],
		["aborted", [["MULTI"], ["SET", "K"], ["SET", "K", "1"], ["EXEC"]]],
	];
	for (const [how, commands] of cases) {
		it(`is refused where a match lies inside it, ${how}`, async () => {
			const relay = await startRelay({ upstream: upstreamOf(redis.url) });
			const k = fresh();
			const seen = relay.observe(setOf(k));
			const c = await rawClient(relay.url);
			c.write(...commands.map((args) => encode(...args.map((a) => (a === "K" ? k : a)))));
			await expect(seen).rejects.toThrow(/transaction/);
			await c.replies(commands.length);
			c.end();
			await expect(relay.close()).rejects.toThrow(/transaction/);
		});
	}
});

describe("holding a request", () => {
	it("keeps it, and what follows on its connection, from Redis until released", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const k = fresh();
		const hold = relay.hold(setOf(k));
		const c = await rawClient(relay.url);
		c.write(encode("SET", k, "1"), encode("PING"));
		const held = await hold;
		await pause(200);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk(null));
		expect(c.got()).toEqual([]);
		held.release();
		expect(await c.replies(2)).toEqual([ok, { kind: "simple", text: "PONG" }]);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk("1"));
		c.end();
		await relay.close();
	});

	it("never sends it where its connection is cut", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const k = fresh();
		const hold = relay.hold(setOf(k));
		const c = await rawClient(relay.url);
		c.write(encode("SET", k, "1"));
		await hold;
		relay.reset("all");
		await c.closed;
		await pause(200);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk(null));
		expect(relay.executions(setOf(k))).toEqual([]);
		await relay.close();
	});
});

describe("observing", () => {
	it("waits for the outcome asked, and counts each request Redis ran", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const k = fresh();
		const wrote = relay.observe(setOf(k));
		const refused = relay.observe(setOf(k), { outcome: "failed" });
		const c = await rawClient(relay.url);
		c.write(encode("SET", k, "1", "NX"), encode("SET", k, "2", "NX"));
		expect((await wrote).reply).toEqual(ok);
		expect((await refused).reply).toEqual(bulk(null));
		expect(relay.executions(setOf(k)).map((e) => e.succeeded)).toEqual([true, false]);
		c.end();
		await relay.close();
	});

	it("names each connection's role from what it sends, and where it goes; new ones go where switched", async () => {
		const relay = await startRelay({
			upstream: upstreamOf(redis.url),
			roleOf: (c) =>
				c.name === "PING" ? "confirming" : c.name === "SET" ? "operations" : undefined,
		});
		const k = fresh();
		const confirming = await rawClient(relay.url);
		const operations = await rawClient(relay.url);
		confirming.write(encode("PING"));
		operations.write(encode("SET", fresh(), "1"));
		await Promise.all([confirming.replies(1), operations.replies(1)]);
		relay.switchUpstream(upstreamOf(other.url));
		relay.reset("operations");
		await operations.closed;
		expect(confirming.isClosed()).toBe(false);
		const moved = await rawClient(relay.url);
		moved.write(encode("SET", k, "1"));
		await moved.replies(1);
		expect(await ask(other.url, "GET", k)).toEqual(bulk("1"));
		expect(await ask(redis.url, "GET", k)).toEqual(bulk(null));
		const open = relay.connections().filter((x) => x.open);
		expect(open.map((x) => [x.role, x.upstream.port])).toEqual([
			["confirming", upstreamOf(redis.url).port],
			["operations", upstreamOf(other.url).port],
		]);
		confirming.end();
		moved.end();
		await relay.close();
	});
});

describe("what the relay cannot read", () => {
	const cases: [string, Buffer][] = [
		["RESP3", encode("HELLO", "3")],
		["a subscription", encode("SUBSCRIBE", "ch")],
		["an inline command", Buffer.from("PING\r\n")],
		["an unsubscription", encode("UNSUBSCRIBE", "a", "b")],
		["a pattern unsubscription", encode("PUNSUBSCRIBE", "a")],
		["a shard unsubscription", encode("SUNSUBSCRIBE", "a")],
		["answers turned off", encode("CLIENT", "REPLY", "OFF")],
		["an answer skipped", encode("client", "reply", "skip")],
	];
	for (const [what, request] of cases) {
		it(`is refused: ${what}, its connection cut`, async () => {
			const relay = await startRelay({ upstream: upstreamOf(redis.url) });
			const c = await rawClient(relay.url);
			c.write(request);
			await Promise.race([c.closed, pause(2_000)]);
			expect(c.isClosed()).toBe(true);
			await expect(relay.close()).rejects.toThrow(/RESP3|subscription|inline|CLIENT REPLY/);
		});
	}
});

describe("what the relay keeps in order and on record", () => {
	it("keeps a frame behind one still delayed, though the delay is lifted meanwhile, both ways", async () => {
		const relay = await signalling();
		const c = await rawClient(relay.url);
		const k = fresh();
		relay.delay(300, "up");
		c.write(encode("SET", k, "1"));
		// The relay has the first SET, delayed, before the delay is lifted.
		await until(() => relay.connections()[0]?.role !== undefined);
		relay.delay(0, "up");
		c.write(encode("SET", k, "2"));
		expect(await c.replies(2)).toEqual([ok, ok]);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk("2"));
		const ping: Match = { request: (x) => x.name === "PING", succeeded: () => true };
		relay.delay(300, "down");
		c.write(encode("PING"));
		await until(() => relay.executions(ping).length === 1);
		relay.delay(0, "down");
		c.write(encode("ECHO", "after"));
		expect(await c.replies(4)).toEqual([ok, ok, { kind: "simple", text: "PONG" }, bulk("after")]);
		c.end();
		await relay.close();
	});

	it("keeps a delayed frame from passing a stall begun meanwhile, both ways, until resumed", async () => {
		const relay = await signalling();
		const c = await rawClient(relay.url);
		const k = fresh();
		relay.delay(200, "up");
		c.write(encode("SET", k, "1"));
		await until(() => relay.connections()[0]?.role !== undefined);
		relay.stall("up");
		await pause(400);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk(null));
		relay.resume();
		expect(await c.replies(1)).toEqual([ok]);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk("1"));
		relay.delay(0, "up");
		const ping: Match = { request: (x) => x.name === "PING", succeeded: () => true };
		relay.delay(200, "down");
		c.write(encode("PING"));
		await until(() => relay.executions(ping).length === 1);
		relay.stall("down");
		await pause(400);
		expect(c.got()).toEqual([ok]);
		relay.resume();
		expect(await c.replies(2)).toEqual([ok, { kind: "simple", text: "PONG" }]);
		c.end();
		await relay.close();
	});

	it("lets a frame kept by a stall out ahead of a later one still delayed, once resumed", async () => {
		const relay = await signalling();
		const c = await rawClient(relay.url);
		const k = fresh();
		relay.delay(300, "up");
		c.write(encode("SET", k, "1"));
		await until(() => relay.connections()[0]?.role !== undefined);
		await pause(100);
		c.write(encode("SET", k, "2"));
		await pause(50);
		relay.stall("up");
		// The first's delay runs out under the stall; the second's has not when it is lifted.
		await pause(200);
		relay.resume();
		expect(await c.replies(2)).toEqual([ok, ok]);
		expect(await ask(redis.url, "GET", k)).toEqual(bulk("2"));
		c.end();
		await relay.close();
	});

	it("refuses a second hold on a connection already held, so one release never lets the other go", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const [a, b] = [fresh(), fresh()];
		const first = relay.hold(setOf(a));
		const second = relay.hold(setOf(b));
		const c = await rawClient(relay.url);
		c.write(encode("SET", a, "1"), encode("SET", b, "1"));
		await first;
		await expect(second).rejects.toThrow(/one hold/);
		c.end();
		await expect(relay.close()).rejects.toThrow(/one hold/);
	});

	it("records and observes the answers read with a dropped one, without passing them on", async () => {
		const server = await tricklingServer([Buffer.from("+OK\r\n"), Buffer.from(":1\r\n")], {
			whole: true,
		});
		const relay = await startRelay({ upstream: server.upstream });
		const incr: Match = {
			request: (c) => c.name === "INCR",
			succeeded: (r) => r.kind === "integer",
		};
		const drop = relay.dropReplyTo(setOf("k"));
		const counted = relay.observe(incr);
		const c = await rawClient(relay.url);
		c.write(encode("SET", "k", "v"), encode("INCR", "n"));
		const dropped = await drop.first;
		await c.closed;
		expect(dropped.collateral).toEqual([
			{ command: { name: "INCR", args: [Buffer.from("n")] }, answered: true },
		]);
		expect(relay.executions(incr)).toHaveLength(1);
		expect((await counted).reply).toEqual({ kind: "integer", value: 1 });
		expect(c.got()).toEqual([]);
		await relay.close();
		await server.stop();
	});

	it("fails its close where a drop asked for never happened", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		relay.dropReplyTo(setOf(fresh()));
		await expect(relay.close()).rejects.toThrow(/never/);
	});

	it("fails its close where a hold asked for never happened", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		void relay.hold(setOf(fresh()));
		await expect(relay.close()).rejects.toThrow(/never/);
	});
});

describe("a caller's code that throws", () => {
	it("fails the relay, its connection cut, and never ends the run", async () => {
		const relay = await startRelay({
			upstream: upstreamOf(redis.url),
			roleOf: (c) => {
				if (c.name === "ECHO") throw new Error("a role that cannot be told");
				return undefined;
			},
		});
		relay.observe({
			request: (c) => {
				if (c.name === "INCR") throw new Error("a match that cannot be read");
				return false;
			},
			succeeded: () => true,
		});
		for (const command of [encode("ECHO", "x"), encode("INCR", fresh())]) {
			const c = await rawClient(relay.url);
			c.write(command);
			await Promise.race([c.closed, pause(2_000)]);
			expect(c.isClosed()).toBe(true);
		}
		await expect(relay.close()).rejects.toThrow(/cannot be told[\s\S]*cannot be read/);
	});

	it("releases a scene waiting on the rule whose match threw, the relay still open", async () => {
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const throws = (where: "request" | "succeeded", name: string): Match => ({
			request: (c) => {
				if (where === "request" && c.name === name) throw new Error(`${name}'s request threw`);
				return c.name === name;
			},
			succeeded: () => {
				if (where === "succeeded") throw new Error(`${name}'s success threw`);
				return true;
			},
		});
		const seen = relay.observe(throws("request", "INCR"));
		const held = relay.hold(throws("request", "DECR"));
		const dropped = relay.dropReplyTo(throws("succeeded", "PING")).first;
		for (const command of [encode("INCR", fresh()), encode("DECR", fresh()), encode("PING")]) {
			const c = await rawClient(relay.url);
			c.write(command);
			await Promise.race([c.closed, pause(2_000)]);
		}
		const within = <T>(p: Promise<T>) =>
			Promise.race([p, pause(2_000).then(() => Promise.reject(new Error("still waiting")))]);
		await expect(within(seen)).rejects.toThrow(/INCR's request threw/);
		await expect(within(held)).rejects.toThrow(/DECR's request threw/);
		await expect(within(dropped)).rejects.toThrow(/PING's success threw/);
		await expect(relay.close()).rejects.toThrow(/threw/);
	});
});

describe("a match made as an object of its own", () => {
	it("is asked with itself as its receiver, as before its predicates were guarded", async () => {
		class SetOf implements Match {
			readonly key: string;
			constructor(key: string) {
				this.key = key;
			}
			request(c: Command) {
				return c.name === "SET" && c.args[0]?.toString() === this.key;
			}
			succeeded(r: Reply) {
				return r.kind === "simple" && r.text === "OK" && this.key.length > 0;
			}
		}
		const relay = await startRelay({ upstream: upstreamOf(redis.url) });
		const k = fresh();
		const seen = relay.observe(new SetOf(k));
		const c = await rawClient(relay.url);
		c.write(encode("SET", k, "1"));
		expect((await seen).reply).toEqual(ok);
		c.end();
		await relay.close();
	});
});
