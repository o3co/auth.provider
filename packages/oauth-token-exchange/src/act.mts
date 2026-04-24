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

import type { ValidatedToken } from "./validator/types.mjs";

/**
 * Build the `act` claim for the token being issued, per RFC 8693 §4.1.
 *
 * Canonical rules:
 * - No actor_token → no `act` on the issued token (impersonation, no trace).
 *                    We do NOT inherit `subject.act`: absence of actor_token
 *                    means the caller is not claiming to delegate for anyone.
 * - Actor provided  → `act.sub = <actor.sub>`. If the subject already had an
 *                     `act` chain, it is nested as `act.act` to preserve the
 *                     full delegation history.
 */
export function buildActClaim(args: {
	subject: ValidatedToken;
	actor: ValidatedToken | undefined;
}): Record<string, unknown> | undefined {
	const { subject, actor } = args;
	if (!actor) return undefined;

	const result: Record<string, unknown> = { sub: actor.sub };
	if (subject.act) {
		result.act = subject.act;
	}
	return result;
}
