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

/**
 * Audit doubles for tests: an `AuditSink` that keeps every event it is handed
 * and can stand in for a sink that is down, and a module that contributes
 * sinks as `auditHooks`.
 */

import type { AuditEvent, AuditSink } from "../audit/types.mjs";
import { defineModule, type Module } from "../modules/manifest/index.mjs";

export interface RecordingAuditSink extends AuditSink {
	readonly kind: "recording";
	/** Every event it was handed, oldest first, each the object it was handed. */
	readonly events: readonly AuditEvent[];
	/** From now on, every record rejects with `error` and keeps nothing. */
	failWith(error: unknown): void;
	/** Record again. */
	recover(): void;
}

export function createRecordingAuditSink(): RecordingAuditSink {
	let events: readonly AuditEvent[] = Object.freeze([]);
	let failure: { readonly error: unknown } | undefined;

	return {
		kind: "recording",
		get events() {
			return events;
		},
		async record(event: AuditEvent): Promise<void> {
			if (failure !== undefined) throw failure.error;
			events = Object.freeze([...events, event]);
		},
		failWith(error: unknown): void {
			failure = { error };
		},
		recover(): void {
			failure = undefined;
		},
	};
}

/**
 * A module named `audit-hooks-<name>` that contributes each of `hooks` as an
 * `auditHooks` entry, in order. `name` is one kebab-case word or more.
 */
export function auditHooksModule(name: string, ...hooks: readonly AuditSink[]): Module {
	return defineModule({
		name: `audit-hooks-${name}`,
		contributes: { auditHooks: hooks.map((hook) => () => hook) },
	});
}
