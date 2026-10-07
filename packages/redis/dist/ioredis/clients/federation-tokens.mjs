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
import { assertPipelineSucceeded, runScript } from "../commands.mjs";
import { redisDurability } from "../durability.mjs";
import { FT_ATTACH, FT_READ_VERSIONED, FT_REMOVE_IF, FT_REPLACE_IF, } from "../scripts/federation-tokens.mjs";
import { COMPARE_AND_DELETE } from "../scripts/lock.mjs";
/** `reply` when it is one of `answers`; anything else is a script this client did not run. */
const answerOf = (reply, answers, operation) => {
    if (answers.includes(reply))
        return reply;
    throw new Error(`federationTokenStoreClient.${operation}: unexpected script reply`);
};
export function makeIoredisFederationTokenStoreClient(io, options = {}) {
    const federationTokenStoreClient = {
        get: (k) => io.get(k),
        // Cast required for overloaded `set`; see the user session store's in `./user-sessions.mts`.
        set: ((k, v, _mode, ttl, cond) => cond === "NX"
            ? io.set(k, v, "PX", ttl, "NX")
            : io.set(k, v, "PX", ttl)),
        del: (k) => io.del(k),
        unlink: (...keys) => io.unlink(...keys),
        // SADD and its expiry in one MULTI/EXEC, so the index key cannot be left without a TTL;
        // NX then GT as in the session stores' `pExpireGT`. MULTI rather than Lua: every command
        // touches one key, which stays valid on Cluster.
        sAddWithTtl: async (key, member, ttlMs) => {
            // EXEC succeeding does not mean the queued commands did: a refused PEXPIRE would void
            // the atomic-TTL guarantee.
            const reply = await io
                .multi()
                .sadd(key, member)
                .pexpire(key, ttlMs, "NX")
                .pexpire(key, ttlMs, "GT")
                .exec();
            assertPipelineSucceeded(reply, "federationTokenStoreClient.sAddWithTtl");
        },
        sRem: (key, member) => io.srem(key, member),
        sScanIterator: (key, opts) => (async function* () {
            const stream = io.sscanStream(key, { count: opts?.COUNT });
            for await (const batch of stream) {
                for (const member of batch)
                    yield member;
            }
        })(),
        scanIterator: ({ MATCH, COUNT }) => (async function* () {
            const stream = io.scanStream({ match: MATCH, count: COUNT });
            for await (const batch of stream) {
                for (const key of batch)
                    yield key;
            }
        })(),
        // Atomic compare-and-delete (advisory-lock release).
        compareAndDelete: async (key, expectedValue) => (await runScript(io, COMPARE_AND_DELETE, [key], [expectedValue])) === 1,
        readVersioned: async (key, input) => {
            const reply = await runScript(io, FT_READ_VERSIONED, [key, input.replayKey], [
                input.candidate,
                String(input.deadlineMs),
                String(input.deadlineMs + input.clockSkewMs + 1),
            ]);
            if (reply === null)
                return null;
            if (!Array.isArray(reply) ||
                reply.length !== 2 ||
                typeof reply[0] !== "string" ||
                typeof reply[1] !== "string") {
                throw new Error("federationTokenStoreClient.readVersioned: unexpected script reply");
            }
            return { raw: reply[0], generation: reply[1] };
        },
        attachRecord: async (key, input) => answerOf(await runScript(io, FT_ATTACH, [key, input.replayKey], [
            String(input.deadlineMs),
            String(input.deadlineMs + input.clockSkewMs + 1),
            input.value,
            String(input.ttlMs),
        ]), ["attached", "late"], "attachRecord"),
        replaceIfGeneration: async (key, input) => answerOf(await runScript(io, FT_REPLACE_IF, [key, input.replayKey], [
            String(input.deadlineMs),
            String(input.deadlineMs + input.clockSkewMs + 1),
            input.expected,
            input.value,
            String(input.ttlMs),
        ]), ["updated", "missing", "conflict", "late"], "replaceIfGeneration"),
        removeIfGeneration: async (key, input) => answerOf(await runScript(io, FT_REMOVE_IF, [key, input.replayKey], [
            String(input.deadlineMs),
            String(input.deadlineMs + input.clockSkewMs + 1),
            input.expected,
        ]), ["removed", "missing", "conflict", "late"], "removeIfGeneration"),
        pExpireGT: async (key, ttlMs) => {
            await io.pexpire(key, ttlMs, "GT");
        },
        durability: () => redisDurability(io, options),
    };
    return federationTokenStoreClient;
}
