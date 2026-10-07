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
export function createRecordingMailSender() {
    let sent = Object.freeze([]);
    let mode = { kind: "deliver" };
    return {
        kind: "recording",
        get sent() {
            return sent;
        },
        async send(mail) {
            if (mode.kind === "fail")
                throw mode.error;
            if (mode.kind === "limit")
                return { outcome: "refused_at_limit" };
            const copy = Object.freeze({
                purpose: mail.purpose,
                subject: mail.subject,
                to: mail.to,
                code: mail.code,
                expiresAtMs: mail.expiresAtMs,
            });
            sent = Object.freeze([...sent, copy]);
            return { outcome: "delivered" };
        },
        refuseAtLimit() {
            mode = { kind: "limit" };
        },
        failWith(error) {
            mode = { kind: "fail", error };
        },
        recover() {
            mode = { kind: "deliver" };
        },
    };
}
