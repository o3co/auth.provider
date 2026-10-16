import type { Started } from "../driver.ts";
import { fakeHttp } from "../fake.ts";

/** An audit event as the target sent it. */
export interface SentEvent {
	readonly kind: string;
	readonly at: number;
	readonly subject?: string;
	readonly attributes?: Readonly<Record<string, string>>;
}

export interface AuditTrail {
	/** The request's result, and the events that arrived from its start until none came for a while. */
	during<T>(
		request: () => Promise<T>,
	): Promise<{ readonly result: T; readonly events: readonly SentEvent[] }>;
}

/** Where a target posts its audit events; stopping it rejects if anything but an event came. */
export interface AuditSink {
	readonly url: string;
	/** `host:port`, plain http at loopback. */
	readonly pair: string;
	readonly trail: AuditTrail;
	stop(): Promise<void>;
}

const quietMs = 300;
const longestMs = 5000;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function auditSink(): Promise<AuditSink> {
	const events: SentEvent[] = [];
	const fake = await fakeHttp((asked) => {
		const event: unknown = JSON.parse(asked.body);
		if (
			asked.method !== "POST" ||
			typeof event !== "object" ||
			event === null ||
			Array.isArray(event)
		)
			throw new Error("not an event posted as one JSON object");
		events.push(event as SentEvent);
		return { status: 204 };
	});
	// Events go out after the answer, so the trail waits for quiet on both sides of a request.
	const quiet = async () => {
		const deadline = Date.now() + longestMs;
		let count = -1;
		while (count !== events.length && Date.now() < deadline) {
			count = events.length;
			await pause(quietMs);
		}
	};
	const trail: AuditTrail = {
		async during(request) {
			await quiet();
			const from = events.length;
			const result = await request();
			await quiet();
			return { result, events: events.slice(from) };
		},
	};
	return { url: `${fake.base}/audit`, pair: new URL(fake.base).host, trail, stop: fake.stop };
}

/** Reading a target's audit events: the need a scene states, and a running target's trail. */
export const auditEvents = Object.freeze({
	need: "audit-http",
	of(started: Started): AuditTrail {
		if (started.kind !== "running" || !started.audit)
			throw new Error("the target sends no audit events; the scene should state the need");
		return started.audit;
	},
});
