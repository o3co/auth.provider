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

/**
 * The composition root's logger, and the value wired into the `logger`
 * ComponentMap slot that every module reads.
 *
 * pino, emitting newline-delimited JSON on stdout — the shape every log
 * aggregator ingests without a parser, and the reason `Logger` was given
 * pino's two-overload call signature in the first place. A pino instance
 * therefore satisfies `Logger` structurally, with no adapter.
 *
 * Two things this closes:
 *
 * - **The slot was never filled.** Only a value satisfying `Logger` can occupy
 *   it, and the logger this template used before exposes four methods with a
 *   narrower call shape. So every module that declares `optional: ["logger"]`
 *   — oauth, session, dpop, mtls, token-exchange — silently fell back to its
 *   own `consoleLogger` default, and nothing an operator configured here
 *   reached any of them.
 * - **`logging.level` is honoured.** pino drops sub-threshold calls before
 *   formatting, so `trace` / `debug` cost nothing in production rather than
 *   being emitted and filtered downstream.
 *
 * `silent` is pino's own name for "emit nothing", so the config vocabulary
 * maps across unchanged.
 */
export function createAppLogger(config: AppConfig): Logger {
	return pino({
		name: "provider",
		level: config.logging.level,
		// `err` is pino's conventional key for an Error, and every structured
		// event in this stack uses it — `logger.error({ err }, "…_error")`.
		// Without the serialiser an Error stringifies to `{}` and the stack is
		// lost exactly where it is needed.
		serializers: { err: stdSerializers.err },
	});
}

/**
 * The stream the audit trail is written on: `name: "audit"`, newline-delimited
 * JSON on stdout, in the same pino envelope as every other line this template
 * emits. One output style, so an aggregator ingests security events and
 * application logs through one parser and separates them on `name`.
 *
 * **It takes no config, and its level is fixed.** That is the point rather
 * than an oversight. `logging.level` is a diagnostics knob — `warn` is an
 * ordinary production setting and `silent` a legitimate one — and an audit
 * trail is evidence, not diagnostics. Routing audit events through the
 * application logger would mean either of those settings silently deleting
 * the record of who authenticated, what was issued, and what was refused:
 * the same drop #287 is about, reached from the operator's side instead of
 * the scaffold's. Where audit events go is chosen by `audit.sink.type`, and
 * that selector has no "none" (#304).
 *
 * A second pino instance rather than a child of the app logger: a child
 * inherits its parent's level, and depending on a level-override subtlety to
 * keep the audit trail alive is exactly the kind of thing that stops being
 * true in a later refactor without anything failing.
 */
export function createAuditLogger(): Logger {
	return pino({
		name: "audit",
		level: "info",
		serializers: { err: stdSerializers.err },
	});
}

/**
 * `AuditSink` writing each event through `auditLogger` — the `"logger"` sink
 * kind this template registers and ships as its default.
 *
 * The event is nested under `audit` rather than spread at the top level:
 * `level`, `time`, `name` and `msg` belong to the log envelope, and a future
 * audit field colliding with one of them would corrupt the line for every
 * consumer. The event type doubles as the message so operators alert on the
 * name — `token.issued.failure`, `authorize.rejected` — the same way they
 * already alert on `session_store_redis_error`.
 *
 * Errors are core's problem, not this function's: `emitAuditEvent` dispatches
 * without awaiting and swallows rejections, because audit recording must never
 * add latency to (or fail) an auth flow.
 */
export function createLoggerAuditSink(auditLogger: Logger): AuditSink {
	return {
		kind: "logger",
		async record(event) {
			auditLogger.info({ audit: event }, event.type);
		},
	};
}
