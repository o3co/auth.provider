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
import { isLoopbackHostname } from "../net/loopback.mjs";
/**
 * Entry fields that were code and are now the verifier's (`readersFor`). An
 * entry still carrying one is refused rather than ignored: ignoring a handle
 * reader would hand the Store a bare `sub` that two issuers can share.
 */
const READER_FIELDS = ["readSubjectHandle", "readScope"];
/**
 * Validate an entry the way boot validates configuration: loudly, naming the
 * field. Shared by the memory registry and by anyone building an entry ahead
 * of registering it.
 */
export function checkAssertionIssuerEntry(entry) {
    for (const field of READER_FIELDS) {
        if (entry[field] !== undefined) {
            throw new Error(`AssertionIssuerEntry(${entry.issuer}): ${field} is not an entry field — an entry is ` +
                "data a store can hold, and a reader is code. Pass it through the verifier's " +
                "readersFor(entry) instead.");
        }
    }
    if (entry.issuer.length === 0) {
        throw new Error("AssertionIssuerEntry: issuer is required — an assertion without a pinned " +
            "issuer is signed by anyone the key belongs to (RFC 7523 §3).");
    }
    if (entry.algorithms.length === 0) {
        throw new Error(`AssertionIssuerEntry(${entry.issuer}): algorithms must name at least one ` +
            "algorithm — omitting it lets jose accept anything the key can verify.");
    }
    if (entry.keys.type === "jwks_uri") {
        let url;
        try {
            url = new URL(entry.keys.uri);
        }
        catch {
            throw new Error(`AssertionIssuerEntry(${entry.issuer}): keys.uri is not an absolute URL: ${entry.keys.uri}`);
        }
        if (url.protocol !== "https:" && !isLoopbackHostname(url.hostname)) {
            throw new Error(`AssertionIssuerEntry(${entry.issuer}): keys.uri must be https — signing ` +
                "keys fetched over plaintext are keys an on-path attacker chose. " +
                "Loopback hosts are exempt for development.");
        }
    }
}
/**
 * The in-memory registry: entries supplied at composition, mutable through
 * the admin surface, gone at restart. A deployment that registers issuers at
 * runtime and needs them to survive a restart implements
 * {@link AssertionIssuerRegistry} over its own store.
 *
 * **Replicas.** Entries supplied here are the same on every replica that runs
 * the same composition, so a static registry is replica-safe. The admin
 * surface is not: `add`, `remove` and `setExpiresAt` change this process only,
 * and an issuer revoked on the replica that took the call stays trusted on
 * every other. A restart does not converge them: it rebuilds the registry from
 * the composition's entries, restoring the revoked issuer on that replica too.
 * `deployment.mode = "multi"` cannot refuse it —
 * the registry sits inside the `assertionVerifier` a composition hands in, not
 * on a module manifest the boot guard reads — so a multi-replica deployment
 * changes the entry list by redeploying, or keeps it in a shared store.
 */
export function createMemoryAssertionIssuerRegistry(entries = []) {
    const byIssuer = new Map();
    const put = (entry) => {
        checkAssertionIssuerEntry(entry);
        if (byIssuer.has(entry.issuer)) {
            throw new Error(`AssertionIssuerRegistry: issuer ${entry.issuer} is already registered — ` +
                "entries are immutable; remove it and add the new one.");
        }
        byIssuer.set(entry.issuer, entry);
    };
    for (const entry of entries)
        put(entry);
    return {
        kind: "memory",
        async findIssuer(issuer) {
            return byIssuer.get(issuer) ?? null;
        },
        async add(entry) {
            put(entry);
        },
        async list() {
            return [...byIssuer.values()];
        },
        async remove(issuer) {
            return byIssuer.delete(issuer);
        },
        async setExpiresAt(issuer, expiresAt) {
            const current = byIssuer.get(issuer);
            if (current === undefined)
                return false;
            const { expiresAt: _dropped, ...rest } = current;
            byIssuer.set(issuer, expiresAt === undefined ? rest : { ...rest, expiresAt });
            return true;
        },
    };
}
