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
import type { AppConfig, AuditSink, Logger } from "@o3co/auth-provider-core";
import { pino, stdSerializers } from "pino";

/** What the logger is built from: the `logging` module's section. */
export type LoggingSettings = NonNullable<AppConfig["logging"]>;

/**
 * The composition root's logger, and the value wired into the `logger` slot
 * every module reads: pino, newline-delimited JSON on stdout, at the
 * `logging` section's level. `Logger` has pino's two-overload call signature, so a pino
 * instance satisfies it with no adapter, and `silent` is pino's own name for
 * "emit nothing", so the config vocabulary maps across unchanged. See the
 * template README, "Logging".
 */
export function createAppLogger(logging: LoggingSettings): Logger {
	return pino({
		name: "provider",
		level: logging.level,
		// `err` is the key every structured event in this stack uses
		// (`logger.error({ err: loggableError(err) }, "…_error")`). Core's
		// projection is plain data with no `message`, so this serialiser hands it
		// through as it is, every cause's fields included. It is here for an
		// Error handed in as it is, which would otherwise stringify to `{}`.
		serializers: { err: stdSerializers.err },
	});
}

/**
 * The stream the audit trail is written on: `name: "audit"`, newline-delimited
 * JSON on stdout in the same pino envelope as every other line.
 *
 * **It takes no config, and its level is fixed**, on purpose: an audit trail
 * is evidence, not diagnostics, and `logging.level` (where `warn` is an
 * ordinary production setting and `silent` a legitimate one) must not delete
 * it. See the template README, "Audit trail". A second pino instance rather
 * than a child of the app logger, because a child inherits its parent's level.
 */
export function createAuditLogger(): Logger {
	return pino({
		name: "audit",
		level: "info",
		serializers: { err: stdSerializers.err },
	});
}

/**
 * `AuditSink` writing each event through `auditLogger`: the `"logger"` sink
 * kind this template registers and ships as its default.
 *
 * The event is nested under `audit`, not spread at the top level: `level`,
 * `time`, `name` and `msg` belong to the log envelope, and an audit field
 * colliding with one would corrupt the line for every consumer. The event
 * type is the message, so operators alert on the name (`token.issued.failure`,
 * `authorize.rejected`) as on `session_store_redis_error`. Errors are core's:
 * `emitAuditEvent` dispatches without awaiting and swallows rejections,
 * because audit recording must never add latency to (or fail) an auth flow.
 */
export function createLoggerAuditSink(auditLogger: Logger): AuditSink {
	return {
		kind: "logger",
		async record(event) {
			auditLogger.info({ audit: event }, event.type);
		},
	};
}
