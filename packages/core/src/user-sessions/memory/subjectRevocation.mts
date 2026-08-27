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

import type { SubjectRevocation } from "../types.mjs";

interface Watermark {
	readonly beforeMs: number;
	readonly expiresAtMs: number;
}

/**
 * In-process Map-backed {@link SubjectRevocation} (#296).
 *
 * GC is lazy — expired watermarks are dropped when read — mirroring
 * `createMemoryAccessTokenDenylist`. No background sweep.
 *
 * A second `revokeBefore` for the same subject takes the **later** watermark
 * rather than the newer call's value. Two credential changes in quick
 * succession must not have the second one, computed on a replica whose clock
 * is behind, move the line backwards and resurrect tokens the first one killed.
 */
export function createInMemorySubjectRevocation(): SubjectRevocation {
	const entries = new Map<string, Watermark>();

	return {
		kind: "memory",

		async revokeBefore(subject, before, expiresAt) {
			const beforeMs = before.getTime();
			const expiresAtMs = expiresAt.getTime();
			const existing = entries.get(subject);
			if (existing !== undefined && existing.expiresAtMs > Date.now()) {
				entries.set(subject, {
					beforeMs: Math.max(existing.beforeMs, beforeMs),
					expiresAtMs: Math.max(existing.expiresAtMs, expiresAtMs),
				});
				return;
			}
			entries.set(subject, { beforeMs, expiresAtMs });
		},

		async revokedBefore(subject) {
			const entry = entries.get(subject);
			if (entry === undefined) return null;
			if (entry.expiresAtMs <= Date.now()) {
				entries.delete(subject);
				return null;
			}
			return new Date(entry.beforeMs);
		},
	};
}
