import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { afterEach, describe, expect, it } from "vitest";
import {
	applying,
	listening,
	type Mark,
	marks,
	type PolicyRule,
	type PolicyUse,
	policies,
	policy,
	type Route,
	routes,
	use,
} from "../../contract.ts";
import http from "../../module.ts";

const runtime = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

let stop: () => Promise<void> = async () => {};
afterEach(async () => {
	await stop();
	stop = async () => {};
});

const site = policy("test.site");
const limit = policy<{ readonly window: { readonly open: boolean } }>("test.limit");
const shut = policy("test.shut");

const ownSite: Mark = {
	guarantee: "own-site",
	policies: [{ policy: site, methods: ["POST", "PUT", "DELETE"] }],
};
const perSource: Mark = {
	guarantee: "per-source",
	policies: [{ policy: limit, methods: ["GET", "POST", "PUT", "DELETE"] }],
};

const rules: readonly PolicyRule[] = [
	applying(site, () => "pass"),
	applying(limit, (_request, options) => (options.window.open ? "pass" : { status: 429 })),
	applying(shut, () => ({ status: 403 })),
];

/** A module contributing the test's rules, these marks, then these routes. */
function owner(list: readonly Route[], given: readonly Mark[] = [ownSite, perSource]): Module {
	return defineModule({ name: "owner" }, (m) => [
		...rules.map((rule) => m.contribute(policies).by(() => rule)),
		...given.map((mark) => m.contribute(marks).by(() => mark)),
		...list.map((route) => m.contribute(routes).by(() => route)),
	]);
}

async function serveWith(module: Module) {
	const app = await assemble({
		modules: [http, module],
		config: { ...kernelConfig(), http: { port: 0 } },
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	return `http://127.0.0.1:${app.get(listening).port()}`;
}

/** The refusals a boot is refused with, as [where, reason]. */
async function refusalsOf(booting: Promise<unknown>) {
	const error = await booting.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(error).toBeInstanceOf(BootRefused);
	return (error as BootRefused).refusals.map((r) => [r.where, r.reason]);
}

const open = { window: { open: true } };
const answered = () => ({ status: 204 });
const post = (path: string, uses: readonly PolicyUse[], more: Partial<Route> = {}): Route => ({
	method: "POST",
	path,
	uses,
	handle: answered,
	...more,
});

describe("a route's declared guarantees", () => {
	it("boots a route whose marked policies keep both, and a GET that changes nothing", async () => {
		const base = await serveWith(
			owner([
				post("/kept", [use(site), use(limit, open)], { changesState: true }),
				{ method: "GET", path: "/read", changesState: false, handle: answered },
			]),
		);
		expect((await fetch(`${base}/kept`, { method: "POST" })).status).toBe(204);
		expect((await fetch(`${base}/read`)).status).toBe(204);
	});

	it("counts a policy only by the mark of its own value, never by its name", async () => {
		const named = policy("test.site");
		const module = defineModule({ name: "named" }, (m) => [
			m.contribute(policies).by(() => applying(named, () => "pass")),
		]);
		const declared = assemble({
			modules: [http, owner([post("/named", [use(named), use(limit, open)])]), module],
			config: { ...kernelConfig(), http: { port: 0 } },
			runtime,
		});
		expect(await refusalsOf(declared)).toEqual([
			[
				"http.routes:POST /named",
				"changes state with no policy marked own-site for POST, nor a reason in crossSite",
			],
		]);
	});

	it("refuses a second mark for one guarantee", async () => {
		const again: Mark = { guarantee: "own-site", policies: [{ policy: shut, methods: ["POST"] }] };
		expect(await refusalsOf(serveWith(owner([], [ownSite, again])))).toEqual([
			["http.marks:own-site", "more than one contribution for the same key"],
		]);
	});

	it("asks a GET to say whether it changes state, and refuses a POST said to change none", async () => {
		const booting = serveWith(
			owner([
				{ method: "GET", path: "/unsaid", unlimited: "counted by the handler", handle: answered },
				post("/said", [use(site), use(limit, open)], { changesState: false }),
			]),
		);
		expect(await refusalsOf(booting)).toEqual([
			["http.routes:GET /unsaid", "a GET route says whether it changes state (changesState)"],
			["http.routes:POST /said", "a POST route changes state; changesState: false is for a GET"],
		]);
	});

	it("takes a mark only for the methods it names: a state-changing GET needs a reason", async () => {
		const get = (uses: readonly PolicyUse[], more: Partial<Route>): Route => ({
			method: "GET",
			path: "/start",
			changesState: true,
			uses,
			handle: answered,
			...more,
		});
		expect(await refusalsOf(serveWith(owner([get([use(site), use(limit, open)], {})])))).toEqual([
			[
				"http.routes:GET /start",
				"changes state with no policy marked own-site for GET, nor a reason in crossSite",
			],
		]);
		const reasoned = get([use(limit, open)], { crossSite: "a navigation the user starts" });
		const base = await serveWith(owner([reasoned]));
		expect((await fetch(`${base}/start`)).status).toBe(204);
	});

	it("refuses a mark and a reason together, an empty reason, and a reason where nothing changes", async () => {
		const booting = serveWith(
			owner([
				post("/both", [use(site), use(limit, open)], { unlimited: "counted elsewhere" }),
				post("/empty", [use(limit, open)], { crossSite: " " }),
				{ method: "GET", path: "/still", changesState: false, crossSite: "x", handle: answered },
			]),
		);
		expect(await refusalsOf(booting)).toEqual([
			[
				"http.routes:POST /both",
				"both a policy marked per-source for POST and a reason in unlimited",
			],
			["http.routes:POST /empty", "an empty reason in crossSite"],
			["http.routes:GET /still", "a reason in crossSite on a route that changes no state"],
		]);
	});

	it("refuses its own-site policy after its per-source one, so a cross-site request spends no window", async () => {
		const booting = serveWith(
			owner([post("/late", [use(limit, open), use(site)], { changesState: true })]),
		);
		expect(await refusalsOf(booting)).toEqual([
			["http.routes:POST /late", "its own-site policy runs after its per-source policy"],
		]);
	});

	it("checks a route that declares nothing as well: a GET must say, and any other must keep both or say why", async () => {
		const booting = serveWith(
			owner([{ method: "GET", path: "/silent", handle: answered }, post("/bare", [])]),
		);
		expect(await refusalsOf(booting)).toEqual([
			["http.routes:GET /silent", "a GET route says whether it changes state (changesState)"],
			[
				"http.routes:POST /bare",
				"changes state with no policy marked own-site for POST, nor a reason in crossSite",
			],
			[
				"http.routes:POST /bare",
				"changes state with no policy marked per-source for POST, nor a reason in unlimited",
			],
		]);
	});

	it("applies what each route used at boot, whatever is changed afterwards", async () => {
		const window = { open: true };
		const uses = [use(limit, { window })];
		const base = await serveWith(
			owner([post("/fixed", uses, { crossSite: "a client's own call" })]),
		);
		uses.push(use(shut));
		window.open = false;
		expect((await fetch(`${base}/fixed`, { method: "POST" })).status).toBe(204);
	});

	it("answers HEAD on a GET that changes state with 405, naming the methods it takes", async () => {
		const base = await serveWith(
			owner([
				{
					method: "GET",
					path: "/end",
					changesState: true,
					uses: [use(limit, open)],
					crossSite: "a top-level navigation the user starts",
					handle: answered,
				},
				post("/end", [use(site), use(limit, open)], { changesState: true }),
				{ method: "GET", path: "/page", changesState: false, handle: () => ({ status: 200 }) },
			]),
		);
		const head = await fetch(`${base}/end`, { method: "HEAD" });
		expect([head.status, head.headers.get("allow")]).toEqual([405, "GET, POST"]);
		expect((await fetch(`${base}/page`, { method: "HEAD" })).status).toBe(200);
	});

	it("never lets a request its marked policy answers reach the handler", async () => {
		let reached = false;
		const blocking: Mark = {
			guarantee: "own-site",
			policies: [{ policy: shut, methods: ["POST"] }],
		};
		const base = await serveWith(
			owner(
				[
					post("/shut", [use(shut), use(limit, open)], {
						changesState: true,
						handle: () => {
							reached = true;
							return { status: 204 };
						},
					}),
				],
				[blocking, perSource],
			),
		);
		expect((await fetch(`${base}/shut`, { method: "POST" })).status).toBe(403);
		expect(reached).toBe(false);
	});
});
