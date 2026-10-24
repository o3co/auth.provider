import { connect } from "node:net";
import { listening, routes } from "@mod/http";
import http from "@mod/http/module";
import { assemble, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { metrics } from "@mod/metrics";
import metricsModule from "@mod/metrics/module";
import { afterEach, expect, it } from "vitest";
import httpOps from "../src/module.ts";

const runtime = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

let stop: () => Promise<void> = async () => {};
afterEach(async () => {
	await stop();
	stop = async () => {};
});

/** A route that takes anything under its path, as a route naming a user or a client may. */
const items = defineModule({ name: "items", takes: [] }, (m) => [
	m.contribute(routes).by(() => ({
		method: "GET",
		path: "/items/*",
		changesState: false,
		handle: () => ({ status: 204 }),
	})),
]);

/** http, metrics and http-ops served together, as a composition has them. */
async function served() {
	const app = await assemble({
		modules: [http, metricsModule, httpOps, items],
		config: { ...kernelConfig(), http: { port: 0 } },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	const series = () => {
		const reading = app
			.get(metrics)
			.read()
			.find((r) => r.name === "http_request_duration_seconds");
		if (reading?.kind !== "histogram") throw new Error("no request-duration histogram");
		return reading.series.map(
			(s) => `${s.labels.method} ${s.labels.route} ${s.labels.status} ${s.count}`,
		);
	};
	const labels = () =>
		JSON.stringify(
			app
				.get(metrics)
				.read()
				.map((r) => r.series.map((s) => s.labels)),
		);
	return { base, series, labels };
}

it("answers both routes through http: HEAD with no body, and a Content-Type with 415", async () => {
	const { base } = await served();
	for (const path of ["/_healthcheck", "/readyz"]) {
		const res = await fetch(`${base}${path}`);
		expect([path, res.status, res.headers.get("cache-control")]).toEqual([path, 200, "no-store"]);
		const head = await fetch(`${base}${path}`, { method: "HEAD" });
		expect([head.status, await head.text()]).toEqual([200, ""]);
		const typed = await fetch(`${base}${path}`, { headers: { "content-type": "text/plain" } });
		expect(typed.status).toBe(415);
	}
});

it("counts the requests http serves, a connection closed before any answer as 499", async () => {
	const { base, series } = await served();
	await fetch(`${base}/_healthcheck`);
	await fetch(`${base}/nowhere`);
	await new Promise<void>((resolve, reject) => {
		const socket = connect(Number(new URL(base).port), "127.0.0.1", () => {
			socket.write("GET /readyz HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n");
			setTimeout(() => socket.destroy(), 50);
		});
		socket.on("close", () => resolve());
		socket.on("error", reject);
	});
	for (let i = 0; i < 100 && series().length < 3; i++) {
		await new Promise((r) => setTimeout(r, 20));
	}
	expect(series().sort()).toEqual([
		"GET /_healthcheck 200 1",
		"GET /readyz 499 1",
		"GET unmatched 404 1",
	]);
});

it("labels a request by the route's declared path, never by what its own path, query or headers hold", async () => {
	const { base, series, labels } = await served();
	await fetch(`${base}/items/alice-4711?token=s3cr3t`, { headers: { "x-user": "bob" } });
	await fetch(`${base}/alice-4711/s3cr3t`);
	for (let i = 0; i < 100 && series().length < 2; i++) {
		await new Promise((r) => setTimeout(r, 20));
	}
	expect(series().sort()).toEqual(["GET /items/* 204 1", "GET unmatched 404 1"]);
	for (const held of ["alice", "4711", "s3cr3t", "token", "bob"]) {
		expect(labels(), held).not.toContain(held);
	}
});
