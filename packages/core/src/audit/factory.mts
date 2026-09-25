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
 * `event` as a sink is handed it: `ip` and `userAgent`, the two fields a
 * route copies from the request, sanitised and capped with
 * {@link auditErrorText} (RFC 6749 NQSCHAR, `?` for anything else, at most
 * 200 characters). Behind `trust
 * proxy`, `req.ip` is what the caller wrote in `X-Forwarded-For`, and a user
 * agent is the caller's own header; over HTTP either can carry a tab, the C1
 * controls and up to the header-size limit, and a composition can hand in
 * anything. A value that is not a string is dropped, never coerced. Every
 * other field is the event's as it was, and an event with neither field gains
 * neither.
 *
 * The one cap for both: an address never approaches it, and a user agent's
 * product tokens — what a dashboard groups on — come first; the longest
 * common ones (an in-app browser's, 210–270 characters) lose only trailing
 * device detail past 200.
 */
function withBoundedRequestFields(event: AuditEvent): AuditEvent {
	if (event.ip === undefined && event.userAgent === undefined) return event;
	const { ip, userAgent, ...rest } = event;
	const boundedIp = auditErrorText(ip);
	const boundedUserAgent = auditErrorText(userAgent);
	return {
		...rest,
		...(boundedIp === undefined ? {} : { ip: boundedIp }),
		...(boundedUserAgent === undefined ? {} : { userAgent: boundedUserAgent }),
	};
}

/**
 * Hands `event` to `sink` with its request fields bounded (see
 * {@link withBoundedRequestFields}), and answers the sink's own promise.
 *
 * The one way a built-in event reaches a sink: {@link emitAuditEvent} calls
 * it and detaches, and an emitter that waits on the sink — federation grants,
 * whose core bounds its audit waits and hands them to a registry a shutdown
 * drains — calls it directly. The log-projection drift guard pins that no
 * other source writes a sink.
 */
export function recordAuditEvent(sink: AuditSink, event: AuditEvent): Promise<void> {
	return sink.record(withBoundedRequestFields(event));
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
	recordAuditEvent(sink, event).catch(() => {
		// intentionally swallowed
	});
	return Promise.resolve();
}
