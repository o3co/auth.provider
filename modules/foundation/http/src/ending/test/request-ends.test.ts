import { connect } from "node:net";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { afterEach, expect, it } from "vitest";
import { listening, type RequestEnd, requestEnds, routes } from "../../contract.ts";
import http from "../../module.ts";

let now = 0;
const runtime = quietRuntime({
	clock: { now: () => now },
	random: { bytes: (n) => new Uint8Array(n) },
});

/** /hang answers only once released, and says when it is reached; fresh for each test. */
let hang = { reached: Promise.withResolvers<void>(), released: Promise.withResolvers<void>() };

let stop: () => Promise<void> = async () => {};
afterEach(async () => {
	await stop();
	stop = async () => {};
	now = 0;
	hang = { reached: Promise.withResolvers<void>(), released: Promise.withResolvers<void>() };
});

const handlers = defineModule({ name: "handlers", takes: [] }, (m) => [
	m.contribute(routes).by(() => ({
		method: "GET",
		changesState: false,
		path: "/slow",
		handle: async () => {
			now += 30;
			return { status: 204 };
		},
	})),
	m.contribute(routes).by(() => ({
		method: "GET",
		changesState: false,
		path: "/items/*",
		handle: () => ({ status: 200 }),
	})),
	m.contribute(routes).by(() => ({
		method: "GET",
		changesState: false,
		path: "/back",
		handle: () => {
			now -= 5000;
			return { status: 200 };
		},
	})),
	m.contribute(routes).by(() => ({
		method: "GET",
		changesState: false,
		path: "/hang",
		handle: async () => {
			hang.reached.resolve();
			await hang.released.promise;
			return { status: 200 };
		},
	})),
]);

/** A module observing each request's end into `ends`. */
function observing(ends: RequestEnd[]): Module {
	return defineModule({ name: "observer", takes: [] }, (m) => [
		m.contribute(requestEnds).by(() => ({ ended: (end) => ends.push(end) })),
	]);
}

async function serveWith(...modules: Module[]) {
	const app = await assemble({
		modules: [http, handlers, ...modules],
		config: { ...kernelConfig(), http: { port: 0 } },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	return `http://127.0.0.1:${app.get(listening).port()}`;
}

const until = async (done: () => boolean) => {
	for (let i = 0; i < 100 && !done(); i++) await new Promise((r) => setTimeout(r, 20));
};

it("tells each request's end once: the method sent, the declared route reached, the status and the time", async () => {
	const ends: RequestEnd[] = [];
	const base = await serveWith(observing(ends));
	await fetch(`${base}/slow`);
	await fetch(`${base}/items/a1b2c3`, { method: "HEAD" });
	await fetch(`${base}/nowhere`);
	await fetch(`${base}/slow`, { method: "PROPFIND" });
	await until(() => ends.length === 4);
	// Strict, so a request that reached no route has no route key at all.
	expect(ends).toStrictEqual([
		{ method: "GET", route: "/slow", status: 204, ms: 30 },
		{ method: "HEAD", route: "/items/*", status: 200, ms: 0 },
		{ method: "GET", status: 404, ms: 0 },
		{ method: "PROPFIND", status: 405, ms: 0 },
	]);
	expect(Object.isFrozen(ends[0])).toBe(true);
});

it("tells a connection closed before any answer as closed, once", async () => {
	const ends: RequestEnd[] = [];
	const base = await serveWith(observing(ends));
	const socket = connect(Number(new URL(base).port), "127.0.0.1", () =>
		socket.write("GET /hang HTTP/1.1\r\nHost: x\r\n\r\n"),
	);
	socket.on("error", () => {});
	await hang.reached.promise;
	socket.destroy();
	await until(() => ends.length > 0);
	// The late answer is written now, and a second end would be told within these turns.
	hang.released.resolve();
	for (let turn = 0; turn < 3; turn++) await new Promise((r) => setImmediate(r));
	expect(ends).toEqual([{ method: "GET", route: "/hang", status: "closed", ms: 0 }]);
});

it("tells a clock set back as 0 ms", async () => {
	const ends: RequestEnd[] = [];
	const base = await serveWith(observing(ends));
	await fetch(`${base}/back`);
	await until(() => ends.length === 1);
	expect(ends[0]?.ms).toBe(0);
});

it("drops an observer's throw, still telling the others and serving", async () => {
	const ends: RequestEnd[] = [];
	const throwing = defineModule({ name: "throwing", takes: [] }, (m) => [
		m.contribute(requestEnds).by(() => ({
			ended: () => {
				throw new Error("boom");
			},
		})),
	]);
	const base = await serveWith(throwing, observing(ends));
	expect((await fetch(`${base}/slow`)).status).toBe(204);
	expect((await fetch(`${base}/slow`)).status).toBe(204);
	await until(() => ends.length === 2);
	expect(ends.map((end) => end.status)).toEqual([204, 204]);
});

it("drops an observer's rejection, raising no unhandled rejection, still telling the others and serving", async () => {
	const unhandled: unknown[] = [];
	const spy = (reason: unknown) => unhandled.push(reason);
	process.on("unhandledRejection", spy);
	try {
		const ends: RequestEnd[] = [];
		const rejecting = defineModule({ name: "rejecting", takes: [] }, (m) => [
			m.contribute(requestEnds).by(() => ({
				ended: async () => {
					throw new Error("boom");
				},
			})),
		]);
		const base = await serveWith(rejecting, observing(ends));
		expect((await fetch(`${base}/slow`)).status).toBe(204);
		expect((await fetch(`${base}/slow`)).status).toBe(204);
		await until(() => ends.length === 2);
		// Node raises an unhandled rejection once the microtasks run out; a macrotask later, it has.
		await new Promise((r) => setTimeout(r, 50));
		expect(unhandled).toEqual([]);
		expect(ends.map((end) => end.status)).toEqual([204, 204]);
	} finally {
		process.off("unhandledRejection", spy);
	}
});
