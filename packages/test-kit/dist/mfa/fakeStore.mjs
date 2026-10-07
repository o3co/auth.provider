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
/**
 * A fake Store: an in-memory HTTP server on a loopback address that answers
 * the Store's MFA endpoints as the wire contract says (core's
 * `mfa/storeWire.mts`; `@o3co/auth-provider-foundation`'s README, "The
 * Store's MFA endpoints"), and the two login endpoints the enrollment witness
 * is read back through, each answering it alike.
 *
 * Guarantees: every record held is answered back as held, one the provider
 * cannot read included; an update is a compare-and-set that writes the
 * changes and nothing else of the record, at the expected version plus one;
 * a subject's records are one set at a store generation, kept as core's
 * conditional-write convention for a set says (docs/adapter-surface.md,
 * "Conditional writes"): every membership write mints a fresh one, an update
 * keeps it, a create and a removal of one record are conditional writes that
 * check it — one without `expectedGeneration` is refused `400`, the reset
 * alone going without one — an emptied set stays as its
 * tombstone until the write-lifetime bound has passed on its clock, and a set
 * held without one is given one by its first list; a conditional write whose
 * `deadlineMs` is at or before its request clock is answered `408` and not
 * applied, checked in the same step as the write; each request is answered
 * by the contract from state it reads and writes without yielding, so
 * concurrent requests are atomic; a request with an
 * absolute or odd target, naming a host other than its own address, with a
 * body over {@link FAKE_STORE_MAX_BODY_BYTES} or not declared JSON is refused
 * and not recorded. `answer` makes an endpoint break the contract on purpose
 * — at once, later, or never — and `holdFactor` holds a record as a Store
 * might, so an adapter's reading of a broken Store can be tested. It keeps
 * every request it records, headers included: test data only.
 */
import { createServer } from "node:http";
import { BUNDLED_STORE_WRITE_LIFETIME_MS, isStorableExpiry, isStoreGeneration, newStoreGeneration, readMfaStoreFactor, readMfaStoreFactorChanges, } from "@o3co/auth-provider-core";
/** The largest request body the fake Store reads: 1 MiB. */
export const FAKE_STORE_MAX_BODY_BYTES = 1024 * 1024;
const PATHS = {
    authenticate: "/authenticate",
    authenticateByToken: "/authenticate-by-token",
    list: "/mfa/factors/list",
    create: "/mfa/factors/create",
    update: "/mfa/factors/update",
    delete: "/mfa/factors/delete",
    markMfaEnrolled: "/mfa/enrolled",
};
const ENDPOINT_BY_PATH = new Map(Object.entries(PATHS).map(([endpoint, path]) => [path, endpoint]));
const isRecord = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
const isVersion = (value) => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
/** The `id` a held record carries as its own string, if it does. */
const heldId = (record) => isRecord(record) && typeof record.id === "string" ? record.id : undefined;
const JSON_HEADERS = { "Content-Type": "application/json" };
const json = (status, value) => ({
    status,
    headers: JSON_HEADERS,
    body: JSON.stringify(value),
});
const empty = (status) => ({ status });
const CONFLICT = json(409, { outcome: "conflict" });
const LATE = empty(408);
/**
 * Whether `value` is a `deadlineMs` the wire carries: a whole instant above
 * 0 within the Date range, as core's codec holds it (`isStorableExpiry`).
 */
const isDeadline = (value) => typeof value === "number" && Number.isInteger(value) && value > 0 && isStorableExpiry(value);
const MISSING = json(404, { outcome: "missing" });
/** The request's body as text, or `undefined` once it passes the cap: the rest is read and dropped. */
function readBody(request) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        request.on("data", (chunk) => {
            size += chunk.byteLength;
            if (size <= FAKE_STORE_MAX_BODY_BYTES)
                chunks.push(chunk);
        });
        request.on("end", () => resolve(size > FAKE_STORE_MAX_BODY_BYTES ? undefined : Buffer.concat(chunks).toString("utf8")));
        request.on("error", reject);
    });
}
/** Whether a `Content-Type` declares JSON, parameters aside. */
const declaresJson = (value) => value?.split(";")[0]?.trim().toLowerCase() === "application/json";
function send(response, answer) {
    response.writeHead(answer.status, { ...(answer.headers ?? {}) });
    response.end(answer.body);
}
/** Starts a fake Store on `127.0.0.1`, on a port of its own. */
export async function startFakeStore(options = {}) {
    const users = options.users ?? [];
    const now = options.now ?? Date.now;
    const requestNow = options.requestNow ?? Date.now;
    /** Whether a conditional write due by `deadlineMs` arrived too late to apply. */
    const late = (deadlineMs) => requestNow() >= deadlineMs;
    const sets = new Map();
    const witness = new Map();
    const answerers = new Map();
    const requests = [];
    /** `subject`'s set, unless it has none or holds a tombstone past its expiry, which it drops. */
    const setOf = (subject) => {
        const set = sets.get(subject);
        if (set?.expiresAtMs === undefined || set.expiresAtMs > now())
            return set;
        sets.delete(subject);
        return undefined;
    };
    const holds = (subject) => setOf(subject)?.records ?? [];
    /**
     * A membership write: `records` as `subject`'s set at a fresh generation,
     * a tombstone's expiry when it is left empty, none when it holds a record.
     */
    const written = (subject, records) => {
        const generation = newStoreGeneration();
        const expiresAtMs = records.length === 0 ? now() + BUNDLED_STORE_WRITE_LIFETIME_MS : undefined;
        sets.set(subject, { records, generation, expiresAtMs });
        return generation;
    };
    const user = (answer) => ({
        ...(answer.claims ?? {}),
        id: answer.id,
        username: answer.username,
        ...(witness.has(answer.id) ? { mfaEnrolled: witness.get(answer.id) } : {}),
    });
    /** The contract's answer to `request`. */
    function contract(request) {
        const body = request.body;
        if (!isRecord(body))
            return empty(400);
        switch (request.endpoint) {
            case "authenticate": {
                const found = users.find((u) => u.username === body.email && u.password === body.password);
                return found === undefined ? empty(401) : json(200, user(found));
            }
            case "authenticateByToken": {
                const { token } = body;
                const found = users.find((u) => typeof token === "string" && u.tokens?.includes(token));
                return found === undefined ? empty(401) : json(200, user(found));
            }
            case "list": {
                const { subject } = body;
                if (typeof subject !== "string")
                    return empty(400);
                const set = setOf(subject);
                if (set === undefined) {
                    return json(200, {
                        factors: [],
                        generation: null,
                    });
                }
                const generation = set.generation ?? newStoreGeneration();
                sets.set(subject, { ...set, generation });
                return json(200, {
                    factors: set.records,
                    generation,
                });
            }
            case "create": {
                const factor = readMfaStoreFactor(body.factor);
                if (factor === undefined)
                    return empty(400);
                // Absent and `null` differ: `null` is "only while the set is absent".
                if (!Object.hasOwn(body, "expectedGeneration"))
                    return empty(400);
                const set = setOf(factor.subject);
                const records = set?.records ?? [];
                const held = records.some((record) => heldId(record) === factor.id);
                const { expectedGeneration: expected, deadlineMs } = body;
                if (expected !== null && !isStoreGeneration(expected))
                    return empty(400);
                if (!isDeadline(deadlineMs))
                    return empty(400);
                if (late(deadlineMs))
                    return LATE;
                // An absent set is at `null`; one held without a generation matches nothing.
                const at = set === undefined ? null : set.generation;
                if (at !== expected || held)
                    return CONFLICT;
                const generation = written(factor.subject, [...records, factor]);
                return json(200, { outcome: "created", generation });
            }
            case "update": {
                const { subject, id, expectedVersion } = body;
                const changes = readMfaStoreFactorChanges(body.changes);
                if (typeof subject !== "string" ||
                    typeof id !== "string" ||
                    !isVersion(expectedVersion) ||
                    expectedVersion === Number.MAX_SAFE_INTEGER ||
                    changes === undefined) {
                    return empty(400);
                }
                const set = setOf(subject);
                const records = set?.records ?? [];
                const index = records.findIndex((record) => heldId(record) === id);
                if (set === undefined || index === -1)
                    return empty(404);
                const current = readMfaStoreFactor(records[index]);
                if (current?.version !== expectedVersion)
                    return empty(409);
                const { label: _label, lastUsedAtMs: _lastUsedAtMs, ...fixed } = current;
                const next = { ...fixed, ...changes, version: expectedVersion + 1 };
                // A member's own update: the set's generation stays.
                sets.set(subject, {
                    ...set,
                    records: records.map((record, i) => (i === index ? next : record)),
                });
                return json(200, { factor: next });
            }
            case "delete": {
                const { subject, id, all } = body;
                if (typeof subject !== "string")
                    return empty(400);
                const conditional = Object.hasOwn(body, "expectedGeneration");
                const set = setOf(subject);
                const records = set?.records ?? [];
                if (all === true && id === undefined && !conditional) {
                    // The reset always wins: the set stays, empty, at a fresh generation.
                    written(subject, []);
                    return empty(records.length > 0 ? 204 : 404);
                }
                if (typeof id !== "string" || all !== undefined || !conditional)
                    return empty(400);
                const kept = records.filter((record) => heldId(record) !== id);
                const { expectedGeneration: expected, deadlineMs } = body;
                if (!isStoreGeneration(expected))
                    return empty(400);
                if (!isDeadline(deadlineMs))
                    return empty(400);
                if (late(deadlineMs))
                    return LATE;
                if (set === undefined)
                    return MISSING;
                if (set.generation !== expected)
                    return CONFLICT;
                if (kept.length === records.length)
                    return MISSING;
                const generation = written(subject, kept);
                return json(200, { outcome: "removed", generation });
            }
            case "markMfaEnrolled": {
                const { subject, enrolled } = body;
                if (typeof subject !== "string" || typeof enrolled !== "boolean")
                    return empty(400);
                if (!users.some((u) => u.id === subject))
                    return empty(404);
                witness.set(subject, enrolled);
                return empty(204);
            }
        }
    }
    /** `127.0.0.1:<port>`, once listening: the one `Host` it answers. */
    let ownHost = "";
    const server = createServer((incoming, response) => {
        void (async () => {
            const text = await readBody(incoming);
            const target = incoming.url ?? "";
            if (!target.startsWith("/") || target.startsWith("//"))
                return send(response, empty(400));
            const endpoint = ENDPOINT_BY_PATH.get(new URL(target, "http://fake").pathname);
            if (endpoint === undefined)
                return send(response, empty(404));
            if (incoming.method !== "POST")
                return send(response, empty(405));
            if (incoming.headers.host !== ownHost)
                return send(response, empty(421));
            if (text === undefined)
                return send(response, empty(413));
            if (!declaresJson(incoming.headers["content-type"]))
                return send(response, empty(415));
            if (options.bearerToken !== undefined &&
                incoming.headers.authorization !== `Bearer ${options.bearerToken}`) {
                return send(response, {
                    status: 401,
                    headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' },
                });
            }
            let body;
            try {
                body = JSON.parse(text);
            }
            catch {
                body = undefined;
            }
            const headers = Object.fromEntries(Object.entries(incoming.headers).flatMap(([name, value]) => typeof value === "string" ? [[name, value]] : []));
            const request = { endpoint, headers, body };
            requests.push(request);
            const answerer = answerers.get(endpoint);
            const told = answerer === undefined ? undefined : await answerer(request);
            send(response, told ?? contract(request));
        })().catch(() => {
            response.destroy();
        });
    });
    await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => resolve());
    });
    const { port } = server.address();
    ownHost = `127.0.0.1:${port}`;
    const origin = `http://${ownHost}`;
    return {
        urls: {
            authenticateUrl: `${origin}${PATHS.authenticate}`,
            authenticateByTokenUrl: `${origin}${PATHS.authenticateByToken}`,
            listUrl: `${origin}${PATHS.list}`,
            createUrl: `${origin}${PATHS.create}`,
            updateUrl: `${origin}${PATHS.update}`,
            deleteUrl: `${origin}${PATHS.delete}`,
            markMfaEnrolledUrl: `${origin}${PATHS.markMfaEnrolled}`,
        },
        requests,
        factors: (subject) => [...holds(subject)],
        enrolled: (subject) => witness.get(subject),
        holdFactor: (subject, record) => {
            const set = setOf(subject);
            sets.set(subject, {
                records: [...(set?.records ?? []), record],
                generation: undefined,
                expiresAtMs: undefined,
            });
        },
        answer: (endpoint, answerer) => {
            if (answerer === undefined)
                answerers.delete(endpoint);
            else
                answerers.set(endpoint, answerer);
        },
        close: () => new Promise((resolve, reject) => {
            server.closeAllConnections();
            server.close((error) => (error ? reject(error) : resolve()));
        }),
    };
}
