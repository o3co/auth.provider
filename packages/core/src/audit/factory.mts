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
 * (`net.isIP`), an IPv6 `%zone` stripped, or nothing. Behind `trust proxy`,
 * `req.ip` is what the caller wrote in `X-Forwarded-For`, and an SIEM that
 * maps the field as an IP type rejects the whole event over a value that is
 * not one — so `X-Forwarded-For: x` must not reach it. The zone goes because
 * it is the caller's text too (`fe80::1%<anything>`) and names an interface
 * on some other host. A value that is not an address is left out rather than
 * kept elsewhere: the event keeps its documented shape, and the proxy that
 * set the header is the one place its raw value can be trusted and is
 * logged.
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
 * `?` for anything else, at most 200 characters) — over HTTP it can carry a
 * tab, the C1 controls and up to the header-size limit, and a composition can
 * hand in anything. A user agent's product tokens, what a dashboard groups
 * on, come first; the longest common ones (an in-app browser's, 210–270
 * characters) lose only trailing device detail past 200. A value that is not
 * a string is dropped, never coerced. The event is copied and the two fields
 * overwritten in place, so its key order is its own; every other field is as
 * it was, and an event with neither field gains neither.
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
 * {@link withBoundedRequestFields}), and answers the sink's own promise. A
 * sink that throws synchronously, or answers something that is not a
 * promise, answers a rejection or a resolution like any other: it never
 * throws into the caller.
 *
 * The one way a built-in event reaches a sink. {@link emitAuditEvent} calls it
 * and detaches. Two emitters call it directly: the federation-grants routes'
 * bridge, which returns the sink's promise because core bounds its audit
 * waits and hands them to a registry a shutdown drains; and oauth's
 * subject-revocation auditor, which neither waits nor lets the promise go
 * unobserved — it logs a rejection (`federation_grant_audit_failed`). The
 * log-projection drift guard pins that no other source writes a sink.
 */
export async function recordAuditEvent(sink: AuditSink, event: AuditEvent): Promise<void> {
	await sink.record(withBoundedRequestFields(event));
}

/**
 * Fire-and-forget audit emitter. Dispatches the event through
 * {@link recordAuditEvent} without awaiting so a slow or failing sink cannot
 * add latency to (or block) the auth flow. Errors are attached to the
 * detached promise and swallowed. No-op when sink is undefined.
 *
 * Returns synchronously as far as the caller is concerned — the sink's
 * promise is observed only by the `.catch` handler below. Callers MAY
 * `await` this function for symmetry; doing so does not wait for the sink.
 */
export function emitAuditEvent(sink: AuditSink | undefined, event: AuditEvent): Promise<void> {
	if (!sink) return Promise.resolve();
	// Detach from the caller's promise chain; errors are intentionally
	// swallowed per spec §2.2.
	void recordAuditEvent(sink, event).catch(() => {
		// intentionally swallowed
	});
	return Promise.resolve();
}
