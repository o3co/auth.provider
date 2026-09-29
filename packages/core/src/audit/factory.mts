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

import { isIP } from "node:net";
import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { auditErrorText } from "../errors/envelope.mjs";
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
 * Hands `event` to `sink` with its request fields bounded (see
 * {@link withBoundedRequestFields}) and answers the sink's own promise. A sink
 * that throws synchronously or answers a non-promise still never throws into
 * the caller.
 *
 * The one way a built-in event reaches a sink (the log-projection drift guard
 * pins it). {@link emitAuditEvent} calls it and detaches. The federation-grants
 * routes' bridge returns its promise, because core bounds audit waits and a
 * shutdown drains them; oauth's subject-revocation auditor neither waits nor
 * leaves it unobserved, logging a rejection (`federation_grant_audit_failed`).
 */
export async function recordAuditEvent(sink: AuditSink, event: AuditEvent): Promise<void> {
	await sink.record(withBoundedRequestFields(event));
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
