import { contract, deepFreeze, defineModule, type Log, type Refusal } from "@mod/kernel";
import { type Counter, counter, instruments } from "@mod/metrics";
import {
	type Audit,
	type AuditEvent,
	type AuditReceiver,
	audit,
	auditReceivers,
} from "./contract.ts";
import { section } from "./section.ts";

/** The built-in receiver: one log line per event, naming the attributes without their values. */
const logReceiver = (log: Log): AuditReceiver => ({
	name: "log",
	receive: async (event) => {
		log.info("audit", {
			kind: event.kind,
			at: event.at,
			...(event.subject === undefined ? {} : { subject: event.subject }),
			...(event.attributes ? { attributes: Object.keys(event.attributes).join(",") } : {}),
		});
	},
});

/** RFC 6749's NQSCHAR: printable ASCII but `"` and `\\`. */
const outsideNqschar = /[^\x20-\x21\x23-\x5b\x5d-\x7e]/gu;
/** The one attribute a request writes as it likes, bounded as 0.17 bounded it; identifiers are left as written. */
const requestText = "userAgent";
/** The most characters it keeps; a longer one is cut, the cut marked. */
const longest = 200;

/** The request's text as receivers get it, as 0.17 bounded it: `?` for each character outside NQSCHAR, at most 200. */
const bounded = (value: string) => {
	const clean = value.replace(outsideNqschar, "?");
	return clean.length <= longest ? clean : `${clean.slice(0, longest - 3)}...`;
};

/** Each named receiver's lost events since boot, as a metric. */
const lostEvents = contract<Counter>("audit.lost-events");

/** Resolves once the signal aborts. */
const abortOf = (signal: AbortSignal) =>
	new Promise<void>((resolve) => {
		if (signal.aborted) resolve();
		else signal.addEventListener("abort", () => resolve(), { once: true });
	});

export default defineModule(
	{ name: "audit", section, replicaSafe: true, takes: [auditReceivers] },
	(m) => [
		m.provide(lostEvents).by((c) => {
			const named = c.section.receivers === "none" ? [] : c.section.receivers;
			const spec = {
				name: "auth_audit_events_lost_total",
				help: "Audit events a receiver lost since boot: past max-pending, failed, or under way at the stop deadline.",
			};
			// A label needs one value at least; with no receiver the counter has no label and no series.
			if (named.length === 0) return counter({ ...spec, labels: {} });
			return counter({ ...spec, labels: { receiver: named } });
		}),
		m.contribute(instruments).by((c) => c.get(lostEvents)),
		m.provide(audit).by(async (c) => {
			const contributed = await c.collect(auditReceivers);
			const named = c.section.receivers === "none" ? [] : c.section.receivers;
			const builtIns = new Map([["log", logReceiver(c.log)]]);
			const known = new Map(builtIns);
			const refusals: Refusal[] = [];
			for (const receiver of contributed) {
				if (builtIns.has(receiver.name)) {
					refusals.push({
						where: "audit.receivers",
						reason: `${receiver.name} is a built-in name`,
					});
				} else if (!named.includes(receiver.name)) {
					refusals.push({
						where: "audit.receivers",
						reason: `${receiver.name} is composed but not named`,
					});
				}
				known.set(receiver.name, receiver);
			}
			// A name written in the list is a configured value: it is told by its place alone, beside the
			// names that are composed, which are the modules' own.
			const composed = [...known.keys()].join(", ") || "none";
			for (const [at, name] of named.entries()) {
				if (!known.has(name)) {
					refusals.push({
						where: `audit.receivers.${at}`,
						reason: `names no composed receiver (composed: ${composed})`,
					});
				}
			}
			if (refusals.length > 0) c.refuseAll(refusals);
			// On every boot: the operator stated that events go nowhere.
			if (named.length === 0) c.log.warn("audit events go nowhere", { receivers: "none" });
			const max = c.section["max-pending"];
			/** One receiver's events under way, lost since boot, and lost since it last took one. */
			const lanes = named.map((name) => ({
				receiver: known.get(name) as AuditReceiver,
				pending: 0,
				lost: 0,
				losing: 0,
			}));
			type Lane = (typeof lanes)[number];
			const counted = await c.get(lostEvents);
			/** Past the stop deadline: what settles after is neither taken nor lost again. */
			let closed = false;
			const underWay = new Set<Promise<void>>();
			/** `failure` is the kind alone (`backlog`, `stopped`, or the error's name), never a message a receiver wrote. */
			const lose = (lane: Lane, failure: string) => {
				lane.lost += 1;
				counted.add({ receiver: lane.receiver.name });
				lane.losing += 1;
				if (lane.losing === 1) {
					c.log.warn("audit receiver losing events", {
						receiver: lane.receiver.name,
						lost: 1,
						failure,
					});
				}
			};
			const took = (lane: Lane) => {
				if (lane.losing === 0) return;
				c.log.warn("audit receiver recovered", { receiver: lane.receiver.name, lost: lane.losing });
				lane.losing = 0;
			};
			// At stop, deliveries under way get until the deadline; what is still under way then is lost.
			c.onStop(async (signal) => {
				await Promise.race([Promise.allSettled([...underWay]), abortOf(signal)]);
				closed = true;
				for (const lane of lanes) {
					for (; lane.pending > 0; lane.pending -= 1) lose(lane, "stopped");
				}
			});
			return Object.freeze<Audit>({
				record: (event) => {
					const { attributes, ...rest } = event;
					// Copied, so freezing the event leaves the emitter's own attributes as they were.
					const copied = attributes
						? {
								attributes: Object.fromEntries(
									Object.entries(attributes).map(([k, v]) => [
										k,
										k === requestText ? bounded(v) : v,
									]),
								),
							}
						: {};
					const stamped: AuditEvent = deepFreeze({ ...rest, ...copied, at: c.clock.now() });
					for (const lane of lanes) {
						if (lane.pending >= max) {
							lose(lane, "backlog");
							continue;
						}
						lane.pending += 1;
						// Deferred, so record returns first, and a receiver that throws at once fails like one that rejects.
						const delivery = Promise.resolve()
							.then(() => lane.receiver.receive(stamped))
							.then(
								() => {
									if (!closed) took(lane);
								},
								(error: unknown) => {
									if (!closed) lose(lane, error instanceof Error ? error.name : "thrown");
								},
							)
							.finally(() => {
								if (!closed) lane.pending -= 1;
								underWay.delete(delivery);
							});
						underWay.add(delivery);
					}
				},
				lost: () => Object.freeze(Object.fromEntries(lanes.map((l) => [l.receiver.name, l.lost]))),
			});
		}),
	],
);
