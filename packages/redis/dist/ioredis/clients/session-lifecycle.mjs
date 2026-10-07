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
import { runScript } from "../commands.mjs";
import { redisDurability } from "../durability.mjs";
import { LC_BEGIN_CLOSE, LC_COMPLETE, LC_INDEX_CONFIRM, LC_INDEX_PAGE, LC_JOIN, LC_OPEN, LC_READ, } from "../scripts/session-lifecycle.mjs";
const unexpected = (operation) => new Error(`sessionLifecycleStoreClient.${operation}: unexpected reply`);
/** `reply` when it is one of `answers`; anything else is a script this client did not run. */
const answerOf = (reply, answers, operation) => {
    if (answers.includes(reply))
        return reply;
    throw unexpected(operation);
};
/** A flat `[field, value, …]` reply of strings as an object; anything else throws. */
const fieldsOf = (reply, operation) => {
    if (!Array.isArray(reply) || reply.length % 2 !== 0)
        throw unexpected(operation);
    const fields = Object.create(null);
    for (let i = 0; i < reply.length; i += 2) {
        const [field, value] = [reply[i], reply[i + 1]];
        if (typeof field !== "string" || typeof value !== "string")
            throw unexpected(operation);
        fields[field] = value;
    }
    return fields;
};
/** An array of strings; anything else throws. */
const stringsOf = (reply, operation) => {
    if (!Array.isArray(reply) || !reply.every((item) => typeof item === "string")) {
        throw unexpected(operation);
    }
    return reply;
};
export function makeIoredisSessionLifecycleStoreClient(io, options = {}) {
    return {
        openRecord: async (key, input) => answerOf(await runScript(io, LC_OPEN, [key, input.replayKey], [
            String(input.deadlineMs),
            String(input.deadlineMs + input.clockSkewMs + 1),
            input.sub,
            String(input.expiresAtMs),
            String(input.retainUntilMs),
            input.generation,
        ]), ["opened", "refused", "late"], "openRecord"),
        joinRecord: async (key, input) => answerOf(await runScript(io, LC_JOIN, [key, input.replayKey], [
            String(input.deadlineMs),
            String(input.deadlineMs + input.clockSkewMs + 1),
            input.item,
            input.data,
            input.generation,
            String(input.maxParticipants),
        ]), ["joined", "closed", "missing", "full", "late"], "joinRecord"),
        beginCloseRecord: async (keys, input) => {
            const reply = await runScript(io, LC_BEGIN_CLOSE, [keys.record, keys.index], [
                String(input.deadlineMs),
                input.generation,
                input.cause,
                String(input.retainMs),
                input.steps.join(","),
                input.perParticipant.join(","),
                keys.sid,
            ]);
            if (reply === "missing" || reply === "late")
                return reply;
            return fieldsOf(reply, "beginCloseRecord");
        },
        completeRecordItem: async (keys, input) => answerOf(await runScript(io, LC_COMPLETE, [keys.record, input.replayKey, keys.index], [
            String(input.deadlineMs),
            String(input.deadlineMs + input.clockSkewMs + 1),
            input.expected,
            input.item,
            input.generation,
            keys.sid,
        ]), ["updated", "closed", "missing", "conflict", "not_pending", "late"], "completeRecordItem"),
        readRecord: async (key) => {
            const fields = fieldsOf(await runScript(io, LC_READ, [key], []), "readRecord");
            return Object.keys(fields).length === 0 ? null : fields;
        },
        closingPage: async (index, after, count) => stringsOf(await runScript(io, LC_INDEX_PAGE, [index], [after === "" ? "-" : `(${after}`, String(count)]), "closingPage"),
        confirmClosing: async (index, sessions) => {
            if (sessions.length === 0)
                return [];
            return stringsOf(await runScript(io, LC_INDEX_CONFIRM, [index, ...sessions.map(({ record }) => record)], sessions.map(({ sid }) => sid)), "confirmClosing");
        },
        durability: () => redisDurability(io, options),
    };
}
