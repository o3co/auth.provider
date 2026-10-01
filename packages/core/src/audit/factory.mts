/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { isIP } from "node:net";
import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { auditErrorText } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import type { Logger } from "../logging/Logger.mjs";
import type { AuditEvent, AuditSink, AuditSinkFactory } from "./types.mjs";

export function createAuditSinkFactory(): AuditSinkFactory {
	return createAdapterFactory<AuditSink>("AuditSink");
}

export function registerBuiltinAuditSinks(factory: AuditSinkFactory): void {
	factory.register("console", () => ({
		kind: "console",
		async record(event) {
			process.stdout.write(`${JSON.stringify(event)}\n`);
		},
	}));
}

/**
 * An event's `ip` as a sink is handed it: an IPv4 or IPv6 address
 * (`net.isIP`) with any IPv6 `%zone` stripped, or nothing. Behind
 * `trust proxy`, `req.ip` is whatever the caller wrote in `X-Forwarded-For`,
 * and a SIEM that maps the field as an IP type rejects the whole event over a
 * non-address. A zone is either caller text or one of this host's own
 * interfaces (`fe80::1%eth0`), which says nothing about the client. A
 * non-address is left out rather than kept elsewhere, so the event keeps its
 * documented shape; an event with no `ip` says the request's address was not
 * an address (check `trust proxy`).
 */
const auditedIp = (value: unknown): string | undefined => {
	if (typeof value !== "string") return undefined;
	const zone = value.indexOf("%");
	if (zone === -1) return isIP(value) === 0 ? undefined : value;
	const address = value.slice(0, zone);
	return isIP(address) === 6 ? address : undefined;
};

/**
 * `event` as a sink is handed it, its two request fields bounded: `ip` an
 * address or nothing ({@link auditedIp}); `userAgent`, the caller's own
 * header, sanitised and capped with {@link auditErrorText} (RFC 6749 NQSCHAR,
 * `?` for anything else, at most 200 characters, which keeps the leading
 * product tokens a dashboard groups on). A non-string value is dropped, never
 * coerced. The event is copied with the two fields overwritten in place, so
 * its key order is kept, and an event with neither field gains neither.
 */
function withBoundedRequestFields(event: AuditEvent): AuditEvent {
	if (event.ip === undefined && event.userAgent === undefined) return event;
	const bounded: { -readonly [K in keyof AuditEvent]: AuditEvent[K] } = { ...event };
	if (event.ip !== undefined) {
		const ip = auditedIp(event.ip);
		if (ip === undefined) delete bounded.ip;
		else bounded.ip = ip;
	}
	if (event.userAgent !== undefined) {
		const userAgent = auditErrorText(event.userAgent);
		if (userAgent === undefined) delete bounded.userAgent;
		else bounded.userAgent = userAgent;
	}
	return bounded;
}

/**
 * The one call of a sink's `record` in the workspace (the log-projection drift
 * guard pins it): {@link recordAuditEvent} and {@link createAuditFanOut} reach
 * every sink through it. It answers whatever the sink answers, and throws
 * what the sink throws.
 */
function handTo(sink: AuditSink, event: AuditEvent): Promise<void> {
	return sink.record(event);
}

/**
 * Hands `event` to `sink` with its request fields bounded (see
 * {@link withBoundedRequestFields}) and answers the sink's own promise. A sink
 * that throws synchronously or answers a non-promise still never throws into
 * the caller.
 *
 * The one way a built-in event reaches a sink. {@link emitAuditEvent} calls it
 * and detaches. The federation-grants routes' bridge returns its promise,
 * because core bounds audit waits and a shutdown drains them; oauth's
 * subject-revocation auditor neither waits nor leaves it unobserved, logging
 * a rejection (`federation_grant_audit_failed`), which a fan-out never gives.
 */
export async function recordAuditEvent(sink: AuditSink, event: AuditEvent): Promise<void> {
	await handTo(sink, withBoundedRequestFields(event));
}

/** What {@link createAuditFanOut} delivers to and reports through. */
export interface AuditFanOutSources {
	/** The `auditSink` slot's own sink, when one fills it: delivered to first. */
	readonly sink?: AuditSink;
	/** The `auditHooks` contributions, in registration order, read at each event. */
	readonly hooks: () => Iterable<AuditSink>;
	/** Where a failing sink is reported, read at each failure; `consoleLogger` when it answers none. */
	readonly logger: () => Logger | undefined;
}

/**
 * The sink core fills the `auditSink` slot with when a module contributes
 * `auditHooks`: each event goes to the slot's own sink, then to every hook,
 * each called at once, in that order, without waiting for the one before.
 *
 * - Every sink is handed one copy of the event, deeply frozen (plain objects,
 *   arrays, and dates, whose setters throw; any other object is handed as it
 *   is, shared), so no sink can change the plain data another reads; the
 *   emitter's own event is left as it was.
 * - Each call is isolated: a rejection, a synchronous throw or an answer that
 *   is not a promise is that sink's failure alone, logged at error as
 *   `audit_sink_failed` with `sink`, the sink's position — 0 the slot's own
 *   sink, `n` the `n`th hook in registration order — and the event's `type`
 *   when it is a string:
 *   nothing else of the event and nothing of the failure, which may quote it.
 *   An event that cannot be copied, or hooks that cannot be read, reach no
 *   sink, each sink known reported failed without a `type`.
 * - An event recorded while a hook's `record` runs — by the hook, or by work
 *   it started in its own async context (a promise chain, a timer, a detached
 *   `emitAuditEvent`) — goes to the slot's own sink alone, or nowhere without
 *   one, and is logged at warn as `audit_sink_reentered` with its `type`: a
 *   hook is never handed an event it caused, so a hook cannot loop. Work the
 *   hook hands to something created outside its context (a queue's consumer,
 *   a pooled connection) carries that thing's context, not the hook's.
 * - `record` resolves once every sink has settled and never rejects. Core
 *   neither retries nor times a sink out.
 *
 * It carries the slot's sink's `kind`, or `audit-hooks` without one.
 */
export function createAuditFanOut(sources: AuditFanOutSources): AuditSink {
	/** Set while a hook's `record` runs, and in the async work it starts. */
	const insideHook = new AsyncLocalStorage<true>();
	return {
		kind: sources.sink?.kind ?? "audit-hooks",
		async record(event: AuditEvent): Promise<void> {
			const reentered = insideHook.getStore() === true;
			const targets: { readonly sink: AuditSink; readonly position: number }[] = [];
			if (sources.sink !== undefined) targets.push({ sink: sources.sink, position: 0 });
			let shared: AuditEvent;
			let type: string | undefined;
			try {
				if (!reentered) {
					let position = 1;
					for (const hook of sources.hooks()) targets.push({ sink: hook, position: position++ });
				}
				shared = frozenCopy(event, new Map()) as AuditEvent;
				// Read once: an event that is not plain data may answer twice.
				const read: unknown = shared.type;
				type = typeof read === "string" ? read : undefined;
			} catch {
				// Handed to no sink: each one known has failed it.
				for (const { position } of targets) reportFailure(sources.logger, position, undefined);
				return;
			}
			if (reentered) report(sources.logger, "warn", { type }, "audit_sink_reentered");
			await Promise.all(
				targets.map(({ sink: target, position }) =>
					(position === 0
						? delivered(target, shared)
						: insideHook.run(true, () => delivered(target, shared))
					).then((ok) => {
						if (!ok) reportFailure(sources.logger, position, type);
					}),
				),
			);
		},
	};
}

/**
 * Whether `target` took `event`: its call isolated, a failure answered
 * `false`. The answer is awaited, so a native promise is observed through the
 * engine's own subscription, whatever its `then` property says.
 */
async function delivered(target: AuditSink, event: AuditEvent): Promise<boolean> {
	let answer: unknown;
	try {
		answer = handTo(target, event);
	} catch {
		return false;
	}
	if (!isThenable(answer)) return false;
	try {
		await answer;
		return true;
	} catch {
		return false;
	}
}

const isThenable = (value: unknown): value is PromiseLike<unknown> => {
	try {
		return typeof (value as { then?: unknown } | null | undefined)?.then === "function";
	} catch {
		return false;
	}
};

function reportFailure(
	logger: () => Logger | undefined,
	position: number,
	type: string | undefined,
): void {
	report(logger, "error", { sink: position, type }, "audit_sink_failed");
}

function report(
	logger: () => Logger | undefined,
	level: "error" | "warn",
	fields: Record<string, unknown>,
	message: string,
): void {
	try {
		(logger() ?? consoleLogger)[level](fields, message);
	} catch {
		// A logger that throws must not fail the fan-out.
	}
}

/** `Date`'s mutators, which a frozen copy shadows: freezing leaves a date's time writable. */
const DATE_SETTERS = Object.getOwnPropertyNames(Date.prototype).filter((name) =>
	name.startsWith("set"),
);

function refuseDateChange(): never {
	throw new TypeError("an audit event's date is read-only");
}

/**
 * A copy of `value` in which every plain object, array and `Date` is copied
 * and frozen — a date's setters refused — and any other value is kept as it
 * is. A value reached twice is copied once, so a cycle ends.
 */
function frozenCopy(value: unknown, copies: Map<object, unknown>): unknown {
	if (value === null || typeof value !== "object") return value;
	const known = copies.get(value);
	if (known !== undefined) return known;
	if (value instanceof Date) {
		const date = new Date(value.getTime());
		for (const setter of DATE_SETTERS) {
			Object.defineProperty(date, setter, { value: refuseDateChange });
		}
		copies.set(value, date);
		return Object.freeze(date);
	}
	if (Array.isArray(value)) {
		const array: unknown[] = [];
		copies.set(value, array);
		for (const item of value) array.push(frozenCopy(item, copies));
		return Object.freeze(array);
	}
	const prototype = Object.getPrototypeOf(value);
	if (prototype !== Object.prototype && prototype !== null) return value;
	const copy: Record<string, unknown> = prototype === null ? Object.create(null) : {};
	copies.set(value, copy);
	for (const key of Object.keys(value)) {
		Object.defineProperty(copy, key, {
			value: frozenCopy((value as Record<string, unknown>)[key], copies),
			enumerable: true,
		});
	}
	return Object.freeze(copy);
}

/**
 * Fire-and-forget audit emitter: dispatches through {@link recordAuditEvent}
 * without awaiting, so a slow or failing sink cannot add latency to or block
 * the auth flow. Sink errors are swallowed. No-op when sink is undefined.
 * Awaiting the returned promise does not wait for the sink.
 */
export function emitAuditEvent(sink: AuditSink | undefined, event: AuditEvent): Promise<void> {
	if (!sink) return Promise.resolve();
	// Detach from the caller's promise chain; errors are intentionally
	// swallowed.
	void recordAuditEvent(sink, event).catch(() => {
		// intentionally swallowed
	});
	return Promise.resolve();
}
