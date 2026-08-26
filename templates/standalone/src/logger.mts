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
import type { AppConfig, Logger } from "@o3co/auth-provider-core";
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
