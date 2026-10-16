import { noStore, type Route } from "@mod/http";

/** `GET /_healthcheck`: 200 regardless of dependencies, checking none; like any route, 415 to a body. */
export function liveness(): Route {
	return {
		method: "GET",
		path: "/_healthcheck",
		takes: ["none"],
		handle: () => ({ status: 200, headers: { ...noStore }, body: { json: { status: "ok" } } }),
	};
}
