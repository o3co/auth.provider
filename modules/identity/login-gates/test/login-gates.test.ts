import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { sessionStandIn } from "@mod/session/testing";
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

async function boot(extra: Module[], gates: Record<string, unknown> = {}, log = runtime.log) {
	const app = await assemble({
		modules: [http, sessionStandIn, subjectRevocationStandIn, gatesModule, ...extra],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": "https://as.example" }),
			"login-gates": gates,
		},
		runtime: { ...runtime, log },
	});
	return app.get(logins);
}

/** Gates `a` and `b`, contributed out of name order, that record each call; and a caller `fed` told of opens. */
function gated({ holding = [] as string[], throwing = [] as string[] } = {}) {
	const ran: string[] = [];
	const given: (LoginFrom | undefined)[] = [];
	const told: [unknown, string][] = [];
	const gate = (name: string) =>
		defineModule({ name: `gate-${name}` }, (m) => [
			m.contribute(loginGates).by(() => ({
				name,
				hold: async (_request, asked, done, carried) => {
					ran.push(`${name}:${asked.subject}:${JSON.stringify(done)}`);
					given.push(carried);
					if (throwing.includes(name)) throw new Unavailable(name);
					return holding.includes(name)
						? { kind: "held" as const, answer: { by: name }, cookies: [`gate=${name}`] }
						: { kind: "pass" as const };
				},
			})),
		]);
	const caller = defineModule({ name: "caller" }, (m) => [
		m.contribute(openedAfterHold).by(() => ({
			caller: "fed",
			opened: async (session, carry) => {
				told.push([session, carry]);
			},
		})),
	]);
	return { gates: [gate("b"), gate("a")], caller, ran, given, told };
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
	const bare = defineModule({ name: "gate-bare" }, (m) => [
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
		const failing = defineModule({ name: "failing" }, (m) => [
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
		defineModule({ name: `source-${name}` }, (m) => [
			m.contribute(amrSources).by(() => ({ name, amr })),
		]);
	const l = await boot([source("one", ["a"]), source("two", ["b", "c"])]);
	expect(l.achievable(["a", "c"])).toBe(true);
	expect(l.achievable([])).toBe(true);
	expect(l.achievable(["a", "d"])).toBe(false);
});

const path = (name: string, at: string) =>
	defineModule({ name }, (m) => [m.contribute(returnPaths).by(() => ({ path: at }))]);

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
