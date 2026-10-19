import { readFileSync } from "node:fs";
import { expect, it, vi } from "vitest";
import { root } from "../../../test/full-app.ts";
import { routesFile, routesIn, routesOf } from "../routes.ts";

// These tests assemble the whole workspace, which is slow when the machine is busy.
vi.setConfig({ testTimeout: 60_000 });

it("writes a route in a line: method, path, the package it is from, its bodies, policies in order, its guarantees, and CORS", () => {
	const route = { owner: "@mod/r", method: "POST", path: "/r/*", policies: ["csrf", "limit"] };
	const reference = routesOf([
		{
			...route,
			takes: ["json", "none"],
			cors: true,
			changesState: true,
			ownSite: { policy: "csrf" },
			perSource: { reason: "counted | by the handler" },
		},
		{ ...route, method: "GET", policies: [], cors: false },
		{ ...route, method: "PUT", policies: [], cors: false, changesState: true },
	]);
	expect(reference).toContain(
		"| POST | `/r/*` | `@mod/r` | json, none | `csrf`, `limit` | yes | `csrf` | counted \\| by the handler | yes |",
	);
	expect(reference).toContain("| GET | `/r/*` | `@mod/r` | form |  |  |  |  |  |");
	expect(reference).toContain("| PUT | `/r/*` | `@mod/r` | form |  | yes |  |  |  |");
	expect(reference).toContain("a mark is its owner's own claim, and a declaration proves nothing");
});

it("finds every route full with every opt-in serves, each by the package it is from", async () => {
	const routes = await routesIn(root);
	expect(routes.find((r) => r.path === "/oauth/token")).toMatchObject({
		owner: "@mod/token-endpoint",
		method: "POST",
	});
	expect(routes.find((r) => r.path === "/session/login")).toMatchObject({
		method: "POST",
		changesState: true,
		ownSite: { policy: "csrf" },
		perSource: { policy: "rate-limit.attempts-per-source" },
	});
	const seen = routes.map((r) => `${r.method} ${r.path}`);
	expect(new Set(seen).size).toBe(seen.length);
});

it("holds, committed, the route reference generated from the workspace as it is now", async () => {
	expect(readFileSync(routesFile(root), "utf8")).toBe(routesOf(await routesIn(root)));
});
