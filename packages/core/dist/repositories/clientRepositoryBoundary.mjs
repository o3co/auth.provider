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
import { auditErrorList, auditErrorText } from "../errors/envelope.mjs";
import { consoleLogger } from "../logging/consoleLogger.mjs";
import { ClientRecordRefusedError } from "./clientRecordRefused.mjs";
import { PublicClientRecordSchema } from "./InMemoryClientRepository.mjs";
import { readPlainFields } from "./userSnapshot.mjs";
/**
 * The fields `PublicClient` declares, each read by name however the record
 * holds it. An entry `PublicClient` does not declare fails to compile here,
 * and a field it declares that this list misses fails to compile below.
 */
const CLIENT_RECORD_FIELDS = [
    "clientId",
    "tokenEndpointAuthMethod",
    "jwks",
    "jwksUri",
    "allowedRedirectUris",
    "allowedScopes",
    "defaultScopes",
    "allowedAudiences",
    "allowedGrantTypes",
    "postLogoutRedirectUris",
    "backchannelLogoutUri",
    "backchannelLogoutSessionRequired",
    "frontchannelLogoutUri",
    "frontchannelLogoutSessionRequired",
    "allowedAzpForFederationToken",
    "allowedFederationGrantConnections",
    "federationGrantRedirectUris",
    "senderConstrained",
    "firstParty",
    "clientName",
    "clientUri",
    "allowPlainPkce",
    "allowExchangeOfTokensIssuedToOthers",
];
const everyDeclaredFieldRead = true;
void everyDeclaredFieldRead;
/** The schema's answer is a `PublicClient`: a field it holds to another type fails to compile. */
const answersPublicClient = (client) => client;
void answersPublicClient;
const schemaJudgesEveryFieldRead = true;
void schemaJudgesEveryFieldRead;
/** Whether `record` is a list, or a shape that cannot be read (a revoked Proxy): not a record. */
function isNotARecord(record) {
    try {
        return Array.isArray(record);
    }
    catch {
        return true;
    }
}
/**
 * `record`'s declared fields as plain data, each read once, by name. A read
 * that throws refuses the record as `<field>: unreadable`: what was thrown
 * can quote the value, so it is dropped, never answered or logged.
 */
function readFields(record) {
    if (isNotARecord(record))
        return { ok: false, reasons: ["not an object"] };
    const copy = {};
    for (const field of CLIENT_RECORD_FIELDS) {
        let plain;
        try {
            plain = readPlainFields(record, [field]);
        }
        catch {
            return { ok: false, reasons: [`${field}: unreadable`] };
        }
        if (!plain.ok)
            return { ok: false, reasons: [`${field}: not plain data`] };
        Object.assign(copy, plain.copy);
    }
    return { ok: true, copy };
}
/**
 * `record`, answered for `clientId`, as the plain validated copy every
 * consumer reads: each field `PublicClient` declares read once, by name,
 * however the record holds it (own data, a prototype getter, an ORM entity, a
 * Proxy), and nothing else of it — never a `clientSecret` beside them. The
 * copy is parsed with its defaults filled, and the parse is copied once more,
 * so what is answered is frozen at every depth: a fresh object per lookup
 * that shares nothing with the record or with another answer. Its
 * `clientId` must be the id that was looked up, and an id no request could
 * name (`isWellFormedClientId`) is refused, as at boot.
 *
 * Refused, with each reason: a record that is not an object, a field whose
 * read throws (`unreadable`), a field holding what JSON does not hold as it
 * is, a field the schema refuses, an id that is not `clientId`.
 */
function readClientRecord(record, clientId) {
    const plain = readFields(record);
    if (!plain.ok)
        return plain;
    const parsed = PublicClientRecordSchema.safeParse(plain.copy);
    if (!parsed.success) {
        return {
            ok: false,
            reasons: parsed.error.issues.map((issue) => `${issue.path.map(String).join(".") || "record"}: ${issue.message}`),
        };
    }
    if (parsed.data.clientId !== clientId) {
        return { ok: false, reasons: ["clientId: not the id that was looked up"] };
    }
    // The parse is a new, mutable object with the defaults filled: copied once
    // more by the same copier, so what is answered is frozen at every depth.
    // It holds only what the frozen copy held and the schema's defaults, so
    // the copy cannot fail.
    const answer = readPlainFields(parsed.data, CLIENT_RECORD_FIELDS);
    if (!answer.ok)
        return { ok: false, reasons: [`${answer.field}: not plain data`] };
    return { ok: true, client: answer.copy };
}
/** How many reasons a refusal's log line keeps. */
const LOGGED_REASONS_MAX = 10;
/** The boundaries this module built, so one is never wrapped again. */
const boundaries = new WeakSet();
/**
 * `inner` behind the boundary: each record `findById` or `authenticate`
 * answers is read once into a plain copy and held to the registration
 * schema, and the copy is what is answered.
 *
 * - A record that fails is refused: `findById` and `authenticate` reject
 *   with a new {@link ClientRecordRefusedError}. Each refusal writes one
 *   `client_record_refused` warn: the `step` (`find` or `authenticate`), the
 *   client id sanitised and capped, and the reasons, at most ten, each
 *   sanitised and capped (`reasonCount` when more). The record itself is
 *   never logged.
 * - `null` or `undefined` is no record: `null`, silently.
 * - A field whose read throws is refused, as `<field>: unreadable`; what was
 *   thrown is dropped. A throw from the logger changes nothing: the refusal
 *   is still the answer.
 * - The repository's own throw is let through as it was thrown. So is an
 *   inner boundary's refusal, which stays a refusal and is not warned again;
 *   anything else is the store's outage.
 *
 * A layer over the boundary keeps a refusal as long as it lets rejections
 * through unchanged (see the file header). A boundary handed to it is
 * answered as it is, never wrapped twice, so it keeps the logger it was
 * first built with; `options` are not read. The boundary is frozen.
 * Building it reads nothing of `inner`. The boundary is always disposable:
 * disposing it reads `inner`'s `Symbol.asyncDispose` then, and calls it when
 * it is a function.
 *
 * The reasons a refusal logs name the field and an entry's position, never a
 * URI (see the file header). The record object is never logged.
 */
export function validatedClientRepository(inner, options = {}) {
    if (boundaries.has(inner))
        return inner;
    const logger = options.logger ?? consoleLogger;
    const admit = (step, clientId, record) => {
        if (record === null || record === undefined)
            return null;
        const reading = typeof record === "object"
            ? readClientRecord(record, clientId)
            : { ok: false, reasons: ["not an object"] };
        if (reading.ok)
            return reading.client;
        // The refusal is the answer whatever the logger does: a logger that
        // throws must not turn it into an outage carrying the logger's error.
        try {
            logger.warn({
                step,
                clientId: auditErrorText(clientId),
                reasons: auditErrorList(reading.reasons, LOGGED_REASONS_MAX),
                ...(reading.reasons.length > LOGGED_REASONS_MAX
                    ? { reasonCount: reading.reasons.length }
                    : {}),
            }, "client_record_refused");
        }
        catch { }
        throw new ClientRecordRefusedError();
    };
    const boundary = {
        findById: async (clientId) => admit("find", clientId, await inner.findById(clientId)),
        authenticate: async (clientId, secret) => admit("authenticate", clientId, await inner.authenticate(clientId, secret)),
        [Symbol.asyncDispose]: async () => {
            const dispose = inner[Symbol.asyncDispose];
            if (typeof dispose === "function")
                await dispose.call(inner);
        },
    };
    // Frozen: it is shared by every reader of the slot, so none can replace
    // a lookup the others read through. It holds no object of its own.
    Object.freeze(boundary);
    boundaries.add(boundary);
    return boundary;
}
