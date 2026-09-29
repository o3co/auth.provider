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

/*
 * `failureSummary`: what a `BootError`'s message says of the error behind it
 * (a factory's throw, the discovery planner's refusal).
 *
 * A boot failure's message ends up in a log, so it follows `loggableError`'s
 * rules and never `String(error)`: a parser's error quotes its input (a typo
 * in a clients file would print other clients' secrets) and a Redis reply
 * echoes the command's arguments. The message is the error's `name` plus
 * `uncappedDetail`'s reading of its message, or the kind alone for a thrown
 * non-Error. The projection's 256-character cap is not applied: a boot
 * refusal's advice (the key to set, the module to wire) is often longer, and
 * its end is what an operator acts on. The error itself stays on the
 * BootError as `cause` and `details.originalError`; a printed BootError shows
 * it by its projection (`util.inspect.custom` in `types.mts`).
 */

import { loggableError, uncappedDetail } from "../logging/loggableError.mjs";

/** `Name: message`; `Name` when the rules keep no message; `a thrown <kind>` for a non-Error. */
export function failureSummary(thrown: unknown): string {
	const projected = loggableError(thrown);
	if (projected.thrown !== undefined) return `a thrown ${projected.thrown}`;
	const message = uncappedDetail(thrown);
	return message === undefined || message === "" ? projected.name : `${projected.name}: ${message}`;
}

/** The message alone by the same rules, or `""` when they keep none. */
export function failureDetail(thrown: unknown): string {
	return uncappedDetail(thrown) ?? "";
}
