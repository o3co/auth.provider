import { afterEach, expect, it } from "vitest";
import { type AuditSink, auditEvents, auditSink } from "../src/audit/audit.ts";

let sink: AuditSink | undefined;
afterEach(async () => {
	await sink?.stop();
	sink = undefined;
});

const send = (url: string, event: unknown) =>
	fetch(url, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(event),
	});

/** The sink's waits, released one at a time by the test: what arrives between them is ordered, not timed. */
const steps = () => {
	const waiting: (() => void)[] = [];
	return {
		pause: () => new Promise<void>((resolve) => waiting.push(resolve)),
		/** Answers once the sink has begun a wait. */
		async begun() {
			while (waiting.length === 0) await new Promise((resolve) => setImmediate(resolve));
		},
		/** Lets the sink's next wait end, once it has begun one. */
		async step() {
			await this.begun();
			waiting.shift()?.();
		},
	};
};

it("gives a request the events that arrived from its start, and none from before", async () => {
	const waits = steps();
	sink = await auditSink({ pause: waits.pause });
	const { url } = sink;
	expect(sink.pair).toBe(new URL(url).host);
	expect((await send(url, { kind: "before", at: 1 })).status).toBe(204);
	const seen = sink.trail.during(async () => {
		await send(url, { kind: "during", at: 2, subject: "s" });
		return "answer";
	});
	// A straggler arriving while the sink waits for quiet before the request is not the request's.
	await send(url, { kind: "before, arriving late", at: 1 });
	await waits.step();
	await waits.step();
	// After the answer, the sink waits for quiet again: what arrives meanwhile is the request's.
	await waits.begun();
	await send(url, { kind: "late", at: 3, attributes: { a: "1" } });
	await waits.step();
	await waits.step();
	expect(await seen).toEqual({
		result: "answer",
		events: [
			{ kind: "during", at: 2, subject: "s" },
			{ kind: "late", at: 3, attributes: { a: "1" } },
		],
	});
	const empty = sink.trail.during(async () => 0);
	await waits.step();
	await waits.step();
	expect((await empty).events).toEqual([]);
});

it("fails the scene when it stops, after anything but an event posted as one JSON object", async () => {
	const broken = await auditSink();
	await fetch(broken.url, { method: "POST", body: "[1]" });
	await fetch(broken.url);
	await expect(broken.stop()).rejects.toThrow(/the fake's script failed/);
});

it("finds the trail of a running target that sends events, and says so where none does", async () => {
	sink = await auditSink();
	const stop = async () => {};
	const running = { kind: "running", baseUrl: "http://x", stop } as const;
	expect(auditEvents.of({ ...running, audit: sink.trail })).toBe(sink.trail);
	expect(() => auditEvents.of(running)).toThrow(/sends no audit events/);
	expect(() => auditEvents.of({ kind: "refused", output: "" })).toThrow(/sends no audit events/);
});
