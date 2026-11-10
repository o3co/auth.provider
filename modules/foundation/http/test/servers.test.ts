import { defineModule, type Module } from "@mod/kernel";
import { describe, expect, it } from "vitest";
import {
	type HttpServer,
	httpServers,
	listening,
	policy,
	type ServerInput,
	use,
} from "../src/contract.ts";
import { boot, handlers, refusalsOf, serveWith } from "../src/serving/test/serve.ts";

/** A server double: keeps what it was given and whether it was drained, and reports this port. */
function double(port: number) {
	const seen: { input?: ServerInput; drained: boolean } = { drained: false };
	const server: HttpServer = {
		serve: async (input) => {
			seen.input = input;
			return {
				port,
				drain: async () => {
					seen.drained = true;
				},
			};
		},
	};
	return { seen, server };
}

function contributing(name: string, server: HttpServer): Module {
	return defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(httpServers).by(() => server),
	]);
}

const unapplied = policy("test.unapplied");
const route = handlers([
	{ method: "GET", path: "/a", handle: () => ({ status: 204 }) },
	{ method: "GET", path: "/b", uses: [use(unapplied)], handle: () => ({ status: 204 }) },
]);

describe("the server serving the routes", () => {
	it("is http's own when none is contributed", async () => {
		const base = await serveWith(
			handlers([{ method: "GET", path: "/a", handle: () => ({ status: 204 }) }]),
		);
		expect((await fetch(`${base}/a`)).status).toBe(204);
	});

	it("is the one contributed: given the declared routes, the settings and the observers at start, drained at stop", async () => {
		const { seen, server } = double(4321);
		const app = await boot(
			{ host: "127.0.0.1", "cors-origins": ["https://app.example"] },
			{ modules: [route, contributing("server", server)] },
		);
		expect(seen.input).toBeUndefined();
		await app.start();
		expect(app.get(listening).port()).toBe(4321);
		expect(seen.input?.routes.map((r) => r.path)).toEqual(["/a", "/b"]);
		expect(seen.input?.settings).toMatchObject({ host: "127.0.0.1", port: 0 });
		expect([...(seen.input?.settings.origins ?? [])]).toEqual(["https://app.example"]);
		expect(seen.input?.ends).toEqual([]);
		await app.stop(1000);
		expect(seen.drained).toBe(true);
	});

	it("is refused at boot when two are contributed", async () => {
		const booting = boot(
			{},
			{
				modules: [contributing("one", double(1).server), contributing("two", double(2).server)],
			},
		);
		expect(await refusalsOf(booting)).toEqual([
			["http.servers", "more than one server serves the routes: compose one"],
		]);
	});
});
