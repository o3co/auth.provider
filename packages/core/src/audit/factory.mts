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
import type { AuditEvent, AuditSinkBase, AuditSinkFactory } from "./types.mjs";

export function createAuditSinkFactory(): AuditSinkFactory {
	return createAdapterFactory<AuditSinkBase>("AuditSink");
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
 * Fire-and-forget audit emitter. Dispatches `sink.record(event)` without
 * awaiting so a slow or failing sink cannot add latency to (or block) the
 * auth flow. Errors are attached to the detached promise and swallowed.
 * No-op when sink is undefined.
 *
 * Returns synchronously as far as the caller is concerned — the sink's
 * promise is observed only by the `.catch` handler below. Callers MAY
 * `await` this function for symmetry; doing so does not wait for the sink.
 */
export function emitAuditEvent(sink: AuditSinkBase | undefined, event: AuditEvent): Promise<void> {
	if (!sink) return Promise.resolve();
	// Detach from the caller's promise chain; errors are intentionally
	// swallowed per spec §2.2.
	sink.record(event).catch(() => {
		// intentionally swallowed
	});
	return Promise.resolve();
}
