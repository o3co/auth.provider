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
import { CONSENT_FIND, CONSENT_GRANT, PENDING_CONSENT_DISCARD, PENDING_CONSENT_SET, PENDING_CONSENT_TAKE, } from "../scripts/consent.mjs";
export function makeIoredisConsentStoreClient(io) {
    // Each indivisible consent operation is one Lua script (see the `LUA_CONSENT_*` and
    // `LUA_PENDING_CONSENT_*` docblocks). A parked request and its session's index share the
    // `{pending}` hash tag, so a key a script derives is in the slot it was routed to.
    const consentStoreClient = {
        async find(key, nowMs) {
            const reply = (await runScript(io, CONSENT_FIND, [key], [String(nowMs)]));
            if (!Array.isArray(reply))
                return null;
            const [scopes, grantedAt, expiresAt] = reply;
            const fields = {
                scopes,
                grantedAt,
                expiresAt: expiresAt ?? undefined,
            };
            return fields;
        },
        async grant(key, input) {
            await runScript(io, CONSENT_GRANT, [key], [
                String(input.nowMs),
                String(input.grantedAt),
                JSON.stringify(input.scopes),
                input.expiry === undefined ? "" : String(input.expiry.expiresAt),
                input.expiry === undefined ? "" : String(Math.ceil(input.expiry.ttlMs)),
            ]);
        },
        async revoke(key) {
            return (await io.del(key)) > 0;
        },
    };
    return consentStoreClient;
}
export function makeIoredisPendingConsentStoreClient(io) {
    const pendingConsentStoreClient = {
        async set(keys, input) {
            await runScript(io, PENDING_CONSENT_SET, [keys.recordKeyPrefix + input.challenge, keys.sessionKeyPrefix + input.sessionId], [
                String(input.nowMs),
                input.challenge,
                input.sessionId,
                String(input.expiresAt),
                String(Math.ceil(input.ttlMs)),
                input.record,
                String(input.perSessionLimit),
                keys.recordKeyPrefix,
                keys.sessionKeyPrefix,
            ]);
        },
        async get(keys, challenge, nowMs) {
            const reply = await runScript(io, PENDING_CONSENT_TAKE, [keys.recordKeyPrefix + challenge], [String(nowMs), challenge, keys.sessionKeyPrefix, "peek"]);
            return typeof reply === "string" ? reply : null;
        },
        async consume(keys, challenge, nowMs) {
            const reply = await runScript(io, PENDING_CONSENT_TAKE, [keys.recordKeyPrefix + challenge], [String(nowMs), challenge, keys.sessionKeyPrefix, "spend"]);
            return typeof reply === "string" ? reply : null;
        },
        async discard(keys, challenge, record) {
            const reply = await runScript(io, PENDING_CONSENT_DISCARD, [keys.recordKeyPrefix + challenge], [record, challenge, keys.sessionKeyPrefix]);
            return reply === 1;
        },
    };
    return pendingConsentStoreClient;
}
