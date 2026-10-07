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
/** `answer`, what a sender's `send` resolved with, as {@link MailSendOutcome}. */
export function mailSendOutcome(answer) {
    try {
        if (typeof answer !== "object" || answer === null || Array.isArray(answer))
            return "outage";
        const prototype = Object.getPrototypeOf(answer);
        if (prototype !== Object.prototype && prototype !== null)
            return "outage";
        const keys = Reflect.ownKeys(answer);
        if (keys.length !== 1 || keys[0] !== "outcome")
            return "outage";
        const descriptor = Reflect.getOwnPropertyDescriptor(answer, "outcome");
        if (descriptor === undefined || !("value" in descriptor))
            return "outage";
        const { value } = descriptor;
        return value === "delivered" || value === "refused_at_limit" ? value : "outage";
    }
    catch {
        return "outage";
    }
}
