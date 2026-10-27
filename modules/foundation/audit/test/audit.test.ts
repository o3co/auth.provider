import { assemble, BootRefused, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { metrics } from "@mod/metrics";
import metricsModule from "@mod/metrics/module";
import { beforeEach, expect, it } from "vitest";
import { type AuditEvent, type AuditReceiver, audit, auditReceivers } from "../src/contract.ts";
import auditModule from "../src/module.ts";
import { section } from "../src/section.ts";

/** The log of the apps booted since the last reset. */
let recorded = recordingLog();
const lines = () => recorded.lines();
const receiving = (name: string, receive: AuditReceiver["receive"]): Module =>
	defineModule({ name: `receiver-${name}`, takes: [] }, (m) => [
		m.contribute(auditReceivers).by(() => ({ name, receive })),
	]);
/** A composition naming `receivers`, with the receiving modules and settings a test adds. */
const boot = async (receivers: unknown, { extra = [] as Module[], settings = {} as object } = {}) =>
	(
		await assemble({
			modules: [auditModule, ...extra],
			config: {
				...kernelConfig(),
				...(receivers === undefined ? {} : { audit: { receivers, ...settings } }),
			},
			runtime: quietRuntime({
				clock: { now: () => 1234 },
				random: { bytes: (n) => new Uint8Array(n) },
				log: recorded.log,
			}),
		})
	).get(audit);
beforeEach(() => {
	recorded = recordingLog();
});
const warnings = () => lines().filter((l) => l.level === "warn");
/** The warnings in a fixed order, since receivers settle in no order of their own. */
const warned = () =>
	warnings()
		.map((l) => [l.event, l.fields])
		.sort((x, y) => JSON.stringify(x).localeCompare(JSON.stringify(y)));
const settled = () => new Promise((resolve) => setTimeout(resolve, 0));

it("hands each event, stamped and frozen, to the named receivers without waiting for them", async () => {
	const got: AuditEvent[] = [];
	let release = () => {};
	const slow = receiving("slow", async (event) => {
		await new Promise<void>((resolve) => {
			release = resolve;
		});
		got.push(event);
	});
	const quick = receiving("quick", async (event) => {
		got.push(event);
	});
	const a = await boot(["slow", "quick"], { extra: [slow, quick] });
	const attributes = { a: "1" };
	const event = { kind: "k", subject: "s", attributes, at: 1 };
	expect(a.record(event)).toBeUndefined();
	expect(got).toEqual([]);
	await settled();
	// Stamped on the composition's clock, whatever the emitter wrote.
	expect(got).toEqual([{ kind: "k", subject: "s", attributes: { a: "1" }, at: 1234 }]);
	expect(Object.isFrozen(got[0])).toBe(true);
	expect(Object.isFrozen(got[0]?.attributes)).toBe(true);
	expect(Object.isFrozen(attributes)).toBe(false);
	release();
	await settled();
	expect(got).toHaveLength(2);
});

it("bounds the request's user agent as 0.17 did, and leaves identifiers as written", async () => {
	const got: AuditEvent[] = [];
	const quick = receiving("quick", async (event) => {
		got.push(event);
	});
	const a = await boot(["quick"], { extra: [quick] });
	const agent = (userAgent: string) => {
		a.record({
			kind: "k",
			subject: "zoë",
			attributes: { userAgent, client: "café-app", scope: "a b" },
		});
	};
	const long = "Mozilla/5.0 ".repeat(30);
	for (const sent of [
		"a\u0000b\u001fc\u007f",
		"first\r\nsecond",
		'say "hi" \\ there',
		"café ☕ 𝄞",
		long,
	])
		agent(sent);
	await settled();
	expect(got.map((e) => e.attributes?.userAgent)).toEqual([
		"a?b?c?",
		"first??second",
		"say ?hi? ? there",
		"caf? ? ?",
		`${long.slice(0, 197)}...`,
	]);
	// The subject and every other attribute are the caller's own words, as written.
	for (const e of got)
		expect([e.subject, e.attributes?.client, e.attributes?.scope]).toEqual([
			"zoë",
			"café-app",
			"a b",
		]);
});

it("counts a failing receiver's lost events and warns once when it starts losing and once when it recovers", async () => {
	const got: string[] = [];
	let failing = true;
	// The kind of failure is warned, never its message, which may hold what the receiver sent.
	const rejecting = receiving("rejecting", async () => {
		if (failing) throw new Error("down: Bearer s3cr3t");
	});
	const refused = Object.assign(new Error("refused: s3cr3t"), { name: "DestinationRefused" });
	const throwing = receiving("throwing", () => {
		throw refused;
	});
	const fine = receiving("fine", async (event) => {
		got.push(event.kind);
	});
	const a = await boot(["rejecting", "throwing", "fine"], { extra: [rejecting, throwing, fine] });
	expect(() => a.record({ kind: "k" })).not.toThrow();
	a.record({ kind: "k" });
	await settled();
	expect(got).toEqual(["k", "k"]);
	expect(a.lost()).toEqual({ rejecting: 2, throwing: 2, fine: 0 });
	expect(warned()).toEqual([
		["audit receiver losing events", { receiver: "rejecting", lost: 1, failure: "Error" }],
		[
			"audit receiver losing events",
			{ receiver: "throwing", lost: 1, failure: "DestinationRefused" },
		],
	]);
	failing = false;
	a.record({ kind: "k" });
	a.record({ kind: "k" });
	await settled();
	expect(a.lost()).toEqual({ rejecting: 2, throwing: 4, fine: 0 });
	expect(warned()).toEqual([
		["audit receiver losing events", { receiver: "rejecting", lost: 1, failure: "Error" }],
		[
			"audit receiver losing events",
			{ receiver: "throwing", lost: 1, failure: "DestinationRefused" },
		],
		["audit receiver recovered", { receiver: "rejecting", lost: 2 }],
	]);
	expect(JSON.stringify(warned())).not.toContain("s3cr3t");
});

it("does not queue an event past a receiver's pending limit, and counts it as lost", async () => {
	const got: string[] = [];
	const waiting: (() => void)[] = [];
	const slow = receiving("slow", async (event) => {
		await new Promise<void>((resolve) => waiting.push(resolve));
		got.push(event.kind);
	});
	const a = await boot(["slow"], { extra: [slow], settings: { "max-pending": 2 } });
	a.record({ kind: "1" });
	a.record({ kind: "2" });
	a.record({ kind: "3" });
	await settled();
	expect(waiting).toHaveLength(2);
	expect(a.lost()).toEqual({ slow: 1 });
	expect(warnings().map((l) => l.fields)).toEqual([
		{ receiver: "slow", lost: 1, failure: "backlog" },
	]);
	for (const release of waiting.splice(0)) release();
	await settled();
	expect(got).toEqual(["1", "2"]);
	expect(warned()).toEqual([
		["audit receiver losing events", { receiver: "slow", lost: 1, failure: "backlog" }],
		["audit receiver recovered", { receiver: "slow", lost: 1 }],
	]);
	a.record({ kind: "4" });
	await settled();
	expect(waiting).toHaveLength(1);
	expect(a.lost()).toEqual({ slow: 1 });
});

it("reads the losses as a frozen count per named receiver", async () => {
	const a = await boot(["log"]);
	expect(a.lost()).toEqual({ log: 0 });
	expect(Object.isFrozen(a.lost())).toBe(true);
	expect((await boot("none")).lost()).toEqual({});
});

it("writes one log line per event, with the attributes' names and never their values [guarantee-8-b]", async () => {
	const a = await boot(["log"]);
	a.record({ kind: "k", subject: "s", attributes: { method: "secret-ish", result: "x" } });
	await settled();
	expect(lines()).toEqual([
		{
			level: "info",
			event: "audit",
			fields: { kind: "k", at: 1234, subject: "s", attributes: "method,result" },
		},
	]);
});

it("delivers nowhere when the section states none", async () => {
	const a = await boot("none");
	a.record({ kind: "k" });
	await settled();
	expect(lines()).toEqual([]);
});

it("refuses to start without the statement, with an unknown name, or with a receiver left unnamed", async () => {
	const other = receiving("other", async () => {});
	const refused: Record<string, () => Promise<unknown>> = {
		"no statement": () => boot(undefined),
		"an empty list": () => boot([]),
		"a name twice": () => boot(["log", "log"]),
		"a name no receiver has": () => boot(["missing"]),
		"a receiver under none": () => boot("none", { extra: [other] }),
		"a receiver left unnamed": () => boot(["log"], { extra: [other] }),
		"a contributed receiver named log": () =>
			boot(["log"], { extra: [receiving("log", async () => {})] }),
		"no pending allowed": () => boot(["log"], { settings: { "max-pending": 0 } }),
		"a pending limit not whole": () => boot(["log"], { settings: { "max-pending": 1.5 } }),
	};
	for (const [name, start] of Object.entries(refused)) {
		await expect(start(), name).rejects.toBeInstanceOf(BootRefused);
	}
	await expect(boot(["log", "other"], { extra: [other] })).resolves.toBeDefined();
});

it("refuses a name no receiver has at its place in the list, never by the name", async () => {
	const refused = await boot(["log", "missing"]).catch((error: unknown) => error);
	expect((refused as BootRefused).refusals).toEqual([
		{ where: "audit.receivers.1", reason: "names no receiver" },
	]);
});

it("says what to name when no receiver is named: one at least, which there are, or none", async () => {
	const told =
		"name at least one receiver: `log`, one a composed module contributes (a generated app's README names them), or `none` to state that events go nowhere";
	for (const receivers of [undefined, []]) {
		const refused = await boot(receivers).catch((error: unknown) => error);
		expect(refused, JSON.stringify(receivers)).toBeInstanceOf(BootRefused);
		expect((refused as BootRefused).refusals).toEqual([{ where: "audit.receivers", reason: told }]);
	}
});

/** An app naming `receivers`, kept whole so a test can stop it and read its metrics. */
const app = (receivers: string[], extra: Module[]) =>
	assemble({
		modules: [auditModule, metricsModule, ...extra],
		config: { ...kernelConfig(), audit: { receivers } },
		runtime: quietRuntime({ log: recorded.log }),
	});
const lostSeries = (assembly: Awaited<ReturnType<typeof app>>) =>
	assembly
		.get(metrics)
		.read()
		.find((reading) => reading.name === "auth_audit_events_lost_total")?.series;

it("waits at stop for the events under way, so a receiver that answers in time loses none", async () => {
	const got: string[] = [];
	const slow = receiving("slow", async (event) => {
		await new Promise((resolve) => setTimeout(resolve, 30));
		got.push(event.kind);
	});
	const assembly = await app(["slow"], [slow]);
	assembly.get(audit).record({ kind: "k" });
	await assembly.stop(1000);
	expect(got).toEqual(["k"]);
	expect(assembly.get(audit).lost()).toEqual({ slow: 0 });
});

it("counts as lost the events still under way at the stop deadline, and stops on time", async () => {
	const hung = receiving("hung", () => new Promise<void>(() => {}));
	const assembly = await app(["hung"], [hung]);
	assembly.get(audit).record({ kind: "k" });
	assembly.get(audit).record({ kind: "k" });
	const started = Date.now();
	await assembly.stop(50);
	expect(Date.now() - started).toBeLessThan(1000);
	expect(assembly.get(audit).lost()).toEqual({ hung: 2 });
	expect(warned()).toContainEqual([
		"audit receiver losing events",
		{ receiver: "hung", lost: 1, failure: "stopped" },
	]);
});

it("counts each receiver's lost events as a metric", async () => {
	const failing = receiving("failing", async () => {
		throw new Error("down");
	});
	const fine = receiving("fine", async () => {});
	const assembly = await app(["failing", "fine"], [failing, fine]);
	assembly.get(audit).record({ kind: "k" });
	assembly.get(audit).record({ kind: "k" });
	await settled();
	expect(lostSeries(assembly)).toEqual([{ labels: { receiver: "failing" }, value: 2 }]);
});

it("lets each receiver hold 1000 deliveries at once when the operator sets no limit", () => {
	expect(section.parse({ receivers: "none" })).toEqual({ receivers: "none", "max-pending": 1000 });
});

it("takes every handle its takes name", async () => {
	const config = { ...kernelConfig(), audit: { receivers: ["log"] } };
	expect((await takesUnused({ modules: [auditModule], config })).audit).toBeUndefined();
});
