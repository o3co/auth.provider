import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { sessions } from "@mod/session";
import { sessionStandIn, stubSessions } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { expect, it } from "vitest";
import {
	amrSources,
	type LoginFrom,
	loginGates,
	logins,
	openedAfterHold,
	returnPaths,
} from "../src/contract.ts";
import gatesModule from "../src/module.ts";

/** A clock that stands still unless a test moves it. */
const now = 1_800_000_000_000;
const runtime = quietRuntime({ clock: { now: () => now } });
const facts = { subject: "alice", amr: ["pwd"], authenticatedAt: now };
const from = { caller: "fed", carry: "sealed" };

async function boot(
	extra: Module[],
	gates: Record<string, unknown> = {},
	log = runtime.log,
	session: Module = sessionStandIn,
) {
	const app = await assemble({
		modules: [http, session, subjectRevocationStandIn, gatesModule, ...extra],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			"login-gates": gates,
		},
		runtime: { ...runtime, log },
	});
	return app.get(logins);
}

/** Gates `a` and `b` (or `names`), contributed out of name order, that record each call; and a caller `fed` told of opens. */
function gated({
	holding = [] as string[],
	throwing = [] as string[],
	refusing = [] as string[],
	rechecking = [] as string[],
	names = ["b", "a"],
} = {}) {
	const ran: string[] = [];
	const given: (LoginFrom | undefined)[] = [];
	const told: [unknown, string][] = [];
	const gate = (name: string) =>
		defineModule({ name: `gate-${name}`, takes: [] }, (m) => [
			m.contribute(loginGates).by(() => ({
				name,
				...(rechecking.includes(name) ? { rechecked: true } : {}),
				hold: async (_request, asked, done, carried) => {
					ran.push(`${name}:${asked.subject}:${JSON.stringify(done)}`);
					given.push(carried);
					if (throwing.includes(name)) throw new Unavailable(name);
					if (refusing.includes(name)) return { kind: "refused" as const };
					return holding.includes(name)
						? { kind: "held" as const, answer: { by: name }, cookies: [`gate=${name}`] }
						: { kind: "pass" as const };
				},
			})),
		]);
	const caller = defineModule({ name: "caller", takes: [] }, (m) => [
		m.contribute(openedAfterHold).by(() => ({
			caller: "fed",
			opened: async (session, carry) => {
				told.push([session, carry]);
			},
		})),
	]);
	return { gates: names.map(gate), caller, ran, given, told };
}

it("asks the gates in the order of their names and stops at the first that holds", async () => {
	const { gates, ran } = gated({ holding: ["a"] });
	const l = await boot(gates);
	expect(await l.login(testRequest(), facts, { go: "/back" })).toEqual({
		kind: "held",
		gate: "a",
		answer: { by: "a" },
		cookies: ["gate=a"],
	});
	expect(ran).toEqual(['a:alice:{"go":"/back"}']);
});

it("answers a hold that sets no cookies with an empty list", async () => {
	const bare = defineModule({ name: "gate-bare", takes: [] }, (m) => [
		m.contribute(loginGates).by(() => ({
			name: "bare",
			hold: async () => ({ kind: "held" as const, answer: null }),
		})),
	]);
	const l = await boot([bare]);
	expect(await l.login(testRequest(), facts)).toEqual({
		kind: "held",
		gate: "bare",
		answer: null,
		cookies: [],
	});
});

it("resumes with the gates after the one that held", async () => {
	const { gates, ran } = gated({ holding: ["a"] });
	const l = await boot(gates);
	expect((await l.resume(testRequest(), facts, "a", { go: "/back" })).kind).toBe("opened");
	expect(ran).toEqual(['b:alice:{"go":"/back"}']);
});

it("refuses to resume a login at or past its deadline, before any gate runs", async () => {
	const { gates, caller, ran } = gated({ holding: ["a"] });
	const l = await boot([...gates, caller]);
	for (const deadline of [now, now - 1]) {
		const late = await l.resume(testRequest(), facts, "a", null, { ...from, deadline });
		expect(late, String(deadline)).toEqual({ kind: "expired" });
	}
	expect(ran).toEqual([]);
	const inTime = await l.resume(testRequest(), facts, "a", null, { ...from, deadline: now + 1 });
	expect(inTime.kind).toBe("opened");
});

it("opens a session once every gate passes", async () => {
	const { gates, ran } = gated();
	const l = await boot(gates);
	expect(await l.login(testRequest(), facts)).toMatchObject({
		kind: "opened",
		cookies: [expect.any(String)],
	});
	expect(ran).toEqual(["a:alice:null", "b:alice:null"]);
});

it("rejects with a gate's error and asks no gate after it", async () => {
	const { gates, ran } = gated({ throwing: ["a"] });
	const l = await boot(gates);
	await expect(l.login(testRequest(), facts)).rejects.toThrow(Unavailable);
	expect(ran).toEqual(["a:alice:null"]);
});

it("refuses to resume after a name no gate has, before any gate runs, as the caller's error", async () => {
	const { gates, ran } = gated();
	const l = await boot(gates);
	for (const after of ["", "0", "c", "A"]) {
		await expect(l.resume(testRequest(), facts, after), after).rejects.toThrow(TypeError);
	}
	expect(ran).toEqual([]);
});

it("tells the caller once a login it asked for opens after a gate held it, with the carry unread", async () => {
	const { gates, caller, given, told } = gated({ holding: ["a", "b"] });
	const l = await boot([...gates, caller]);
	expect((await l.login(testRequest(), facts, null, from)).kind).toBe("held");
	expect((await l.resume(testRequest(), facts, "a", null, from)).kind).toBe("held");
	expect(given).toEqual([from, from]);
	expect(told).toEqual([]);
	const opened = await l.resume(testRequest(), facts, "b", null, from);
	expect(opened.kind).toBe("opened");
	expect(told).toEqual([[opened.kind === "opened" ? opened.session : undefined, "sealed"]]);
});

it("does not tell the caller of a login that opens without a hold, or of one resumed without its from", async () => {
	const { gates, caller, told } = gated();
	const l = await boot([...gates, caller]);
	expect((await l.login(testRequest(), facts, null, from)).kind).toBe("opened");
	expect((await l.resume(testRequest(), facts, "a", null)).kind).toBe("opened");
	expect(told).toEqual([]);
});

it("refuses a from naming no caller before any gate runs, as the caller's error", async () => {
	const { gates, caller, ran } = gated();
	const l = await boot([...gates, caller]);
	const nobody = { caller: "nobody", carry: "x" };
	await expect(l.login(testRequest(), facts, null, nobody)).rejects.toThrow(TypeError);
	await expect(l.resume(testRequest(), facts, "a", null, nobody)).rejects.toThrow(TypeError);
	expect(ran).toEqual([]);
});

it("still opens the login when the caller's opened throws, and logs the caller and the error's kind only", async () => {
	for (const [thrown, kind] of [
		[new RangeError("sealed"), "RangeError"],
		["sealed", "string"],
	]) {
		const recorded = recordingLog();
		const failing = defineModule({ name: "failing", takes: [] }, (m) => [
			m.contribute(openedAfterHold).by(() => ({
				caller: "fed",
				opened: async () => {
					throw thrown;
				},
			})),
		]);
		const l = await boot([...gated().gates, failing], {}, recorded.log);
		expect((await l.resume(testRequest(), facts, "a", null, from)).kind).toBe("opened");
		expect(
			recorded
				.lines()
				.filter((line) => line.level === "error")
				.map((line) => [line.event, line.fields]),
		).toEqual([["login-gates.opened_failed", { caller: "fed", kind }]]);
	}
});

it("answers whether the declared ways of logging in can prove every one of a set of amr", async () => {
	const source = (name: string, amr: string[]) =>
		defineModule({ name: `source-${name}`, takes: [] }, (m) => [
			m.contribute(amrSources).by(() => ({ name, amr })),
		]);
	const l = await boot([source("one", ["a"]), source("two", ["b", "c"])]);
	expect(l.achievable(["a", "c"])).toBe(true);
	expect(l.achievable([])).toBe(true);
	expect(l.achievable(["a", "d"])).toBe(false);
});

const path = (name: string, at: string) =>
	defineModule({ name, takes: [] }, (m) => [m.contribute(returnPaths).by(() => ({ path: at }))]);

it("lets a login return only to a listed target exactly, or a contributed path on the public origin", async () => {
	const l = await boot([path("authorize", "/oauth/authorize"), path("device", "/device")], {
		"return-targets": ["https://app.example/"],
	});
	for (const allowed of [
		"https://app.example/",
		"https://as.example/oauth/authorize?client_id=app&state=x",
		"https://as.example/device?user_code=x",
	]) {
		expect(l.returnAllowed(allowed), allowed).toBe(true);
	}
	for (const near of [
		"https://app.example",
		"https://app.example/?",
		"HTTPS://app.example/",
		"https://app.example/#x",
		"https://app.example/x",
		"https://as.example/oauth/authorize/x?y=1",
		"https://as.example/oauth/other?y=1",
		"https://as.example/oauth/authorize?x=1#frag",
		"https://as.example/oauth/authorize?x=1#",
		"https://u:p@as.example/oauth/authorize?x=1",
		"https://as.example/oauth/x/../authorize?x=1",
		// Spellings the URL parser rewrites to the contributed path: a login returns as written only.
		"https://as.example/oauth/authorize/../authorize?x=1",
		"https://as.example/oauth/authorize/%2e%2e/authorize?x=1",
		"https://as.example/oauth/authorize/.?x=1",
		"https://as.example/oauth\\authorize?x=1",
		"https://as.example\\oauth/authorize?x=1",
		"https://as.example:8443/oauth/authorize?x=1",
		"http://as.example/oauth/authorize?x=1",
		"https://evil.example/oauth/authorize?x=1",
		"/oauth/authorize?x=1",
		"not a url",
	]) {
		expect(l.returnAllowed(near), near).toBe(false);
	}
	expect((await boot([])).returnAllowed("https://app.example/")).toBe(false);
});

it("lets a login return one name segment below a path contributed so, and nowhere deeper or around it", async () => {
	const below = defineModule({ name: "federation", takes: [] }, (m) => [
		m.contribute(returnPaths).by(() => ({ path: "/session/oauth/federation", segment: true })),
	]);
	const l = await boot([below, path("device", "/device")]);
	for (const allowed of [
		"https://as.example/session/oauth/federation/corp?link=1",
		"https://as.example/session/oauth/federation/idp-2",
		"https://as.example/session/oauth/federation/A_b-9?x=1",
	]) {
		expect(l.returnAllowed(allowed), allowed).toBe(true);
	}
	for (const near of [
		// The path itself, two segments below, and the callback under a name.
		"https://as.example/session/oauth/federation?link=1",
		"https://as.example/session/oauth/federation/corp/callback?code=x",
		"https://as.example/session/oauth/federation/corp/x",
		// An empty segment, a dot segment, and an encoded or doubled slash.
		"https://as.example/session/oauth/federation/?link=1",
		"https://as.example/session/oauth/federation//corp",
		"https://as.example/session/oauth/federation/..?link=1",
		"https://as.example/session/oauth/federation/.?link=1",
		"https://as.example/session/oauth/federation/x/../corp?link=1",
		"https://as.example/session/oauth/federation/corp%2Fcallback",
		"https://as.example/session/oauth/federation/%2E%2E",
		"https://as.example/session/oauth/federation/c%41rp",
		// Another origin, a port, and a fragment.
		"https://evil.example/session/oauth/federation/corp",
		"https://as.example:8443/session/oauth/federation/corp",
		"https://as.example/session/oauth/federation/corp#x",
		// A path contributed whole takes nothing below it.
		"https://as.example/device/corp",
		// A dot is no name's, nor a trailing slash; letters past ASCII are none.
		"https://as.example/session/oauth/federation/corp.name",
		"https://as.example/session/oauth/federation/corp/",
		"https://as.example/session/oauth/federation/c\u00f3rp",
		"https://as.example/session/oauth/federation/c%C3%B3rp",
		// Spellings the URL parser rewrites to one segment below: a login returns as written only.
		"https://as.example/session/oauth/federation/corp/../corp",
		"https://as.example/session/oauth/federation/corp/%2e%2e/cor",
		"https://as.example/session/oauth/federation\\corp",
		"https://as.example\\session/oauth/federation/corp",
	]) {
		expect(l.returnAllowed(near), near).toBe(false);
	}
	// The path contributed whole too, beside its segment: each takes its own.
	const both = await boot([
		below,
		defineModule({ name: "federation-whole", takes: [] }, (m) => [
			m.contribute(returnPaths).by(() => ({ path: "/session/oauth/federation" })),
		]),
	]);
	expect(
		[
			"https://as.example/session/oauth/federation?x=1",
			"https://as.example/session/oauth/federation/corp",
			"https://as.example/session/oauth/federation/corp/x",
		].map((target) => both.returnAllowed(target)),
	).toEqual([true, true, false]);
	// A doubled slash at the root is no name below any path.
	expect(l.returnAllowed("https://as.example//corp")).toBe(false);
	// A segment is a name: letters, digits, `-` or `_`, up to 64.
	expect(l.returnAllowed(`https://as.example/session/oauth/federation/${"a".repeat(64)}`)).toBe(
		true,
	);
	expect(l.returnAllowed(`https://as.example/session/oauth/federation/${"a".repeat(65)}`)).toBe(
		false,
	);
});

it("refuses to start with a return path taking a segment below the root, or below a path ending in a slash", async () => {
	for (const at of ["/", "/session/"]) {
		const below = defineModule({ name: "below", takes: [] }, (m) => [
			m.contribute(returnPaths).by(() => ({ path: at, segment: true })),
		]);
		const refused = await boot([below]).catch((error: unknown) => error);
		expect(BootRefused.is(refused), at).toBe(true);
		expect((refused as BootRefused).refusals, at).toEqual([
			{
				where: "login-gates",
				reason: `a return path taking a segment below it is a path below the root, not ending in a slash: ${at}`,
			},
		]);
	}
});

it("refuses a return target with whitespace or a control character anywhere, though the URL parser drops some", async () => {
	const l = await boot([path("device", "/device")]);
	expect(l.returnAllowed("https://as.example/device?x=1")).toBe(true);
	for (const spaced of [
		"https://as.example/device\t?x=1",
		"https://as.example/device\r\n?x=1",
		"https://as.example/de\nvice?x=1",
		"https://as.example/device?x=1 ",
		" https://as.example/device?x=1",
		"https://as.example/device?x=1\u0000",
		"https://as.example/device?x=\u007f",
		"https://as.example/device?x=\u0085",
		"https://as.example/device?x= ",
		"https://as.example/device?x= ",
	]) {
		expect(l.returnAllowed(spaced), JSON.stringify(spaced)).toBe(false);
	}
});

it("refuses to start with a return target that is not an https URL (http only on a loopback host) kept as written", async () => {
	for (const target of [
		"javascript:alert(1)",
		"http://app.example/",
		"https://u@app.example/",
		"https://app.example/#/home",
		"HTTPS://app.example/",
	]) {
		await expect(boot([], { "return-targets": [target] }), target).rejects.toThrow(BootRefused);
	}
});

it("starts with a return target as http on a loopback host, and refuses http on any other host", async () => {
	const local = ["http://localhost:3000/", "http://127.0.0.1:3000/home", "http://[::1]:3000/"];
	const l = await boot([], { "return-targets": local });
	for (const target of local) expect(l.returnAllowed(target), target).toBe(true);
	for (const target of [
		"http://app.example/",
		"http://localhost.localdomain/",
		"http://0.0.0.0:3000/",
	]) {
		const refused = await boot([], { "return-targets": [target] }).catch((e: unknown) => e);
		expect(refused, target).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals, target).toEqual([
			{ where: "login-gates.return-targets.0", reason: "a URL: http only on a loopback host" },
		]);
	}
});

it("opens the session at the authentication time the way of logging in reported, unknown included, through a hold too", async () => {
	const { gates } = gated({ holding: ["a"] });
	const l = await boot(gates);
	const at = now - 5_000;
	const resumed = await l.resume(testRequest(), { ...facts, authenticatedAt: at }, "a");
	expect(resumed.kind === "opened" && resumed.session.context.authenticatedAt).toBe(at);
	const unknown = await l.resume(testRequest(), { ...facts, authenticatedAt: "unknown" }, "a");
	expect(unknown.kind === "opened" && unknown.session.context.authenticatedAtUnknown).toBe(true);
	const plain = await boot(gated().gates);
	const opened = await plain.login(testRequest(), { ...facts, authenticatedAt: at });
	expect(opened.kind === "opened" && opened.session.context.authenticatedAt).toBe(at);
});

it("reads no return targets when the operator sets none", () => {
	expect(gatesModule.section?.parse({})).toEqual({ "return-targets": [] });
});

/** Sessions that count the opens asked of them and open none: a test that opens one fails. */
function unopened() {
	const asked = { opens: 0 };
	const module = defineModule({ name: "session", takes: [] }, (m) => [
		m.provide(sessions).by(() =>
			stubSessions({
				complete: async () => {
					asked.opens += 1;
					throw new Error("no session opens in this test");
				},
			}),
		),
	]);
	return { asked, module };
}

it("ends a login at the first gate that refuses, with no session, no cookies and no gate after it", async () => {
	const { gates, ran } = gated({ refusing: ["a"] });
	const { asked, module } = unopened();
	const l = await boot(gates, {}, runtime.log, module);
	expect(await l.login(testRequest(), facts)).toEqual({ kind: "refused", gate: "a", cookies: [] });
	expect(ran).toEqual(["a:alice:null"]);
	expect(asked.opens).toBe(0);
});

it("asks every rechecked gate before the one that held again on resume, by name and first, never the gates that hold", async () => {
	const { gates, ran } = gated({
		names: ["d", "c", "b", "a", "0"],
		holding: ["c"],
		rechecking: ["a", "b", "d"],
	});
	const l = await boot(gates);
	expect((await l.login(testRequest(), facts)).kind).toBe("held");
	ran.length = 0;
	expect((await l.resume(testRequest(), facts, "c")).kind).toBe("opened");
	// `0` passed already and is not rechecked; `d`, after the hold, runs once as any gate after it.
	expect(ran).toEqual(["a:alice:null", "b:alice:null", "d:alice:null"]);
});

it("refuses a resumed login at the first rechecked gate that refuses, with no session, no gate after it and no caller told", async () => {
	const { gates, caller, ran, told } = gated({
		names: ["d", "c", "b", "a"],
		holding: ["c"],
		rechecking: ["a", "b"],
		refusing: ["b"],
	});
	const { asked, module } = unopened();
	const l = await boot([...gates, caller], {}, runtime.log, module);
	expect(await l.resume(testRequest(), facts, "c", null, from)).toEqual({
		kind: "refused",
		gate: "b",
		cookies: [],
	});
	expect(ran).toEqual(["a:alice:null", "b:alice:null"]);
	expect([asked.opens, told]).toEqual([0, []]);
});

it("answers expired at or past the deadline before any rechecked gate runs", async () => {
	const { gates, caller, ran } = gated({ names: ["b", "a"], holding: ["b"], rechecking: ["a"] });
	const l = await boot([...gates, caller]);
	expect(await l.resume(testRequest(), facts, "b", null, { ...from, deadline: now })).toEqual({
		kind: "expired",
	});
	expect(ran).toEqual([]);
});

it("rejects with a rechecked gate's error, or throws TypeError where one holds, with no session and no gate after it", async () => {
	const cases: [{ throwing?: string[]; holding: string[] }, (error: unknown) => boolean][] = [
		[{ throwing: ["a"], holding: ["b"] }, isUnavailable],
		[{ holding: ["a", "b"] }, (error) => error instanceof TypeError],
	];
	for (const [failing, expected] of cases) {
		const { gates, ran } = gated({ names: ["c", "b", "a"], rechecking: ["a"], ...failing });
		const { asked, module } = unopened();
		const l = await boot(gates, {}, runtime.log, module);
		await expect(l.resume(testRequest(), facts, "b")).rejects.toSatisfy(expected);
		expect([ran, asked.opens]).toEqual([["a:alice:null"], 0]);
	}
});

it("resumes through the gates composed now: one added before the hold runs only when rechecked, and the hold's own must be there", async () => {
	const held = gated({ names: ["b"], holding: ["b"] });
	const l = await boot(held.gates);
	expect((await l.login(testRequest(), facts)).kind).toBe("held");
	// The composition changes before the resume: two gates come before `b`, one of them rechecked.
	const current = gated({ names: ["b", "a", "0"], holding: ["b"], rechecking: ["a"] });
	const later = await boot(current.gates);
	expect((await later.resume(testRequest(), facts, "b")).kind).toBe("opened");
	expect(current.ran).toEqual(["a:alice:null"]);
	// Without the gate that held, the resume is the caller's error, before any gate runs.
	const without = gated({ names: ["a"], rechecking: ["a"] });
	await expect(
		(await boot(without.gates)).resume(testRequest(), facts, "b"),
	).rejects.toBeInstanceOf(TypeError);
	expect(without.ran).toEqual([]);
});

it("takes every handle its takes name", async () => {
	const modules = [http, sessionStandIn, subjectRevocationStandIn, gatesModule];
	const config = { ...kernelConfig(), ...httpConfig({ "public-origin": "https://as.example" }) };
	expect(await takesUnused({ modules, config })).toEqual({});
});
