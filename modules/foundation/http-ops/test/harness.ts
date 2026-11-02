import {
	type RequestEnd,
	type RequestEndObserver,
	type Route,
	requestEnds,
	routes,
} from "@mod/http";
import { testRequest } from "@mod/http/testing";
import {
	assemble,
	contract,
	defineModule,
	kernelConfig,
	type Module,
	type Runtime,
} from "@mod/kernel";
import httpOps from "../src/module.ts";

/** What http would collect from http-ops and the other modules: the routes and the observers. */
const seen = contract<{
	readonly routes: readonly Route[];
	readonly ends: readonly RequestEndObserver[];
}>("test.seen");

/** Stands where http collects, so http-ops is tested without http's server. */
const collecting = defineModule(
	{ name: "collecting", replicaSafe: true, takes: [requestEnds, routes] },
	(m) => [
		m.provide(seen).by(async (c) => ({
			routes: await c.collect(routes),
			ends: await c.collect(requestEnds),
		})),
	],
);

/** Assembles http-ops with these modules; finds a route and tells the observers a request's end. */
export async function assembled(
	modules: readonly Module[],
	runtime: Runtime,
	settings: Record<string, unknown> = {},
) {
	const app = await assemble({
		modules: [httpOps, collecting, ...modules],
		config: { ...kernelConfig(), "http-ops": settings },
		runtime,
	});
	const { routes: all, ends } = app.get(seen);
	const route = (method: string, path: string) => {
		const found = all.find((r) => r.method === method && r.path === path);
		if (found === undefined) throw new Error(`no route ${method} ${path}`);
		return found;
	};
	/** The route's answer to a GET of its path. */
	const get = (path: string) => route("GET", path).handle(testRequest({ path }));
	const end = (told: RequestEnd) => {
		for (const observer of ends) observer.ended(told);
	};
	return { app, route, get, end };
}
