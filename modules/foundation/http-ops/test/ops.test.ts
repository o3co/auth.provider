import { routes } from "@mod/http";
import { BootRefused, defineModule } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { metrics } from "@mod/metrics";
import metricsModule from "@mod/metrics/module";
import { describe, expect, it } from "vitest";
import { assembled } from "./harness.ts";

const runtime = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

const handlers = defineModule({ name: "handlers" }, (m) => [
	m
		.contribute(routes)
		.by(() => ({ method: "GET", path: "/slow", handle: () => ({ status: 204 }) })),
	m.contribute(routes).by(() => ({
		method: "POST",
		path: "/items/*",
		handle: () => ({ status: 500 }),
	})),
]);

/** The series of the request-duration histogram, as "method route status": count. */
function seriesOf(app: Awaited<ReturnType<typeof assembled>>["app"]) {
	const reading = app
		.get(metrics)
		.read()
		.find((r) => r.name === "http_request_duration_seconds");
	if (reading?.kind !== "histogram") throw new Error("no request-duration histogram");
	return Object.fromEntries(
		reading.series.map((s) => [`${s.labels.method} ${s.labels.route} ${s.labels.status}`, s]),
	);
}

describe("liveness", () => {
	it("answers 200 and ok, never to be cached, checking no dependency", async () => {
		const { get } = await assembled([], runtime);
		expect(await get("/_healthcheck")).toEqual({
			status: 200,
			headers: { "cache-control": "no-store", pragma: "no-cache" },
			body: { json: { status: "ok" } },
		});
	});

	it("takes no body and uses no policy, as /readyz", async () => {
		const { route } = await assembled([], runtime);
		for (const path of ["/_healthcheck", "/readyz"]) {
			expect(route("GET", path)).toMatchObject({ takes: ["none"] });
			expect(route("GET", path).uses).toBeUndefined();
		}
	});

	it("refuses boot when another module takes the same route", async () => {
		const taken = defineModule({ name: "other" }, (m) => [
			m.contribute(routes).by(() => ({
				method: "GET",
				path: "/_healthcheck",
				handle: () => ({ status: 204 }),
			})),
		]);
		const error = await assembled([taken], runtime).catch((e: unknown) => e);
		expect(error).toBeInstanceOf(BootRefused);
		expect((error as BootRefused).refusals.map((r) => r.where)).toEqual([
			"http.routes:GET /_healthcheck",
		]);
	});
});

describe("request duration", () => {
	it("counts each request's end once by method, the declared route and the status written", async () => {
		const { app, end } = await assembled([metricsModule, handlers], runtime);
		end({ method: "GET", route: "/slow", status: 204, ms: 30 });
		end({ method: "HEAD", route: "/slow", status: 204, ms: 0 });
		end({ method: "POST", route: "/items/*", status: 500, ms: 0 });
		end({ method: "GET", route: "/_healthcheck", status: 200, ms: 0 });
		const series = seriesOf(app);
		expect(Object.keys(series).sort()).toEqual([
			"GET /_healthcheck 200",
			"GET /slow 204",
			"HEAD /slow 204",
			"POST /items/* 500",
		]);
		expect(series["GET /slow 204"]).toMatchObject({ count: 1, sum: 0.03 });
		expect(series["POST /items/* 500"]?.count).toBe(1);
	});

	it("labels requests no route took as unmatched, and methods outside the set as other", async () => {
		const { app, end } = await assembled([metricsModule, handlers], runtime);
		end({ method: "GET", status: 404, ms: 0 });
		end({ method: "PUT", status: 405, ms: 0 });
		end({ method: "PROPFIND", status: 405, ms: 0 });
		end({ method: "OPTIONS", status: 204, ms: 0 });
		expect(Object.keys(seriesOf(app)).sort()).toEqual([
			"GET unmatched 404",
			"OPTIONS unmatched 204",
			"PUT unmatched 405",
			"other unmatched 405",
		]);
	});

	it("counts a connection closed before any answer as 499", async () => {
		const { app, end } = await assembled([metricsModule, handlers], runtime);
		end({ method: "GET", route: "/slow", status: "closed", ms: 0 });
		expect(seriesOf(app)["GET /slow 499"]?.count).toBe(1);
	});

	it("drops a status outside its labels without throwing", async () => {
		const { app, end } = await assembled([metricsModule, handlers], runtime);
		expect(() => end({ method: "GET", route: "/slow", status: 600, ms: 0 })).not.toThrow();
		end({ method: "GET", route: "/slow", status: 204, ms: 0 });
		expect(Object.keys(seriesOf(app))).toEqual(["GET /slow 204"]);
	});
});
