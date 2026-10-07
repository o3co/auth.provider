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
 * `failureSummary`: what a `BootError`'s message says of the error behind
 * it — a factory's throw, the discovery planner's refusal.
 *
 * A boot failure ends the process, and whatever prints it (Node's
 * unhandled-rejection printer, a host's logger) writes the message to a log.
 * The message used to be the error flattened with `String(...)`: a parser's
 * error quotes its input and js-yaml's the lines around the fault, so a typo
 * in a clients file wrote other clients' secrets to stderr, a Redis reply
 * put the command's arguments there, and a thrown string went in whole. The
 * message now names the error by `loggableError`'s rules: its `name`, and
 * its message as the projection reads it (`uncappedDetail`: nothing of a
 * SyntaxError's or a YAMLException's text, a Redis reply's echoed arguments
 * cut, on one line); for a thrown
 * value that is not an Error, its kind alone. Not the projection's 256
 * character cap: a boot refusal's advice — the config key to set, the module
 * to wire — is often longer, and its end is what an operator acts on. The
 * error itself stays on the BootError as `cause` (and
 * `details.originalError`), for a caller that reads it; printed, a BootError
 * shows it by its projection (its `util.inspect.custom`, in `types.mts`), so
 * the message is not the only safe part of what the process ends with.
 */
import { loggableError, uncappedDetail } from "../logging/loggableError.mjs";
/** `Name: message`; `Name` when the rules keep no message; `a thrown <kind>` for a non-Error. */
export function failureSummary(thrown) {
    const projected = loggableError(thrown);
    if (projected.thrown !== undefined)
        return `a thrown ${projected.thrown}`;
    const message = uncappedDetail(thrown);
    return message === undefined || message === "" ? projected.name : `${projected.name}: ${message}`;
}
/** The message alone by the same rules, or `""` when they keep none. */
export function failureDetail(thrown) {
    return uncappedDetail(thrown) ?? "";
}
