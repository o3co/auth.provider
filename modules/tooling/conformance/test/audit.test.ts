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

it("gives a request the events that arrived from its start, and none from before", async () => {
	sink = await auditSink();
	const { url } = sink;
	expect(sink.pair).toBe(new URL(url).host);
	expect((await send(url, { kind: "before", at: 1 })).status).toBe(204);
	setTimeout(() => void send(url, { kind: "before, arriving late", at: 1 }), 50);
	const seen = await sink.trail.during(async () => {
		await send(url, { kind: "during", at: 2, subject: "s" });
		setTimeout(() => void send(url, { kind: "late", at: 3, attributes: { a: "1" } }), 50);
		return "answer";
	});
	expect(seen).toEqual({
		result: "answer",
		events: [
			{ kind: "during", at: 2, subject: "s" },
			{ kind: "late", at: 3, attributes: { a: "1" } },
		],
	});
	expect((await sink.trail.during(async () => 0)).events).toEqual([]);
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
