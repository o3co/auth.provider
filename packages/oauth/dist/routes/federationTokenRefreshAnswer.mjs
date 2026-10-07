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
 * Reading an adapter's refresh answer: each field read once behind a guard,
 * its lifetime judged through core's reading and capped at the route's
 * maximum, its token type judged, and the rules that bound the scope it
 * names. Nothing here writes, logs or answers, and no lifetime field makes it throw.
 */
import { canonicalScope, canonicalTokenType, parseScopeTokens, readUpstreamTokenLifetime, } from "@o3co/auth-provider-core";
import { isUsableToken } from "./federationTokenCredential.mjs";
/*
 * An adapter's refresh answer is unverified third-party data: every field of
 * `RefreshedTokens` is optional, and core holds the same contract to the same
 * bar in `federation-grants/retrieve.mts`.
 */
/** No refreshed token is accepted with less than this left (ms) when its answer is read. */
export const REFRESH_FLOOR_MS = 1000;
/**
 * One field of an adapter's answer, or `undefined` if its getter throws: an
 * exception would escape the structured refusal and lose the rotated refresh
 * token. `unreadable` records which: a throwing getter is never read as an
 * absent field.
 */
const readField = (source, key, unreadable) => {
    try {
        return source[key];
    }
    catch {
        unreadable.add(key);
        return undefined;
    }
};
/**
 * Which reading an answer is. A getter that threw (`readField` → `undefined`)
 * is unusable, not omitted: omitted means the full grant, so collapsing the
 * two would let an adapter widen the scope by failing to be read.
 */
const classifyAnsweredScope = (answer, unreadable) => {
    if (unreadable.has("scope"))
        return { kind: "unusable" };
    if (answer.scope === undefined)
        return { kind: "omitted" };
    const named = parseScopeTokens(answer.scope);
    return named.length > 0 ? { kind: "named", value: named.join(" ") } : { kind: "unusable" };
};
export const narrowedScope = (answered, stored, granted) => {
    const storedValue = typeof stored === "string" ? stored : undefined;
    // The ceiling has to satisfy the same rule as the answer: a `granted` that
    // parses to nothing names no scope, whatever its characters, so it falls
    // through to the current scope rather than standing as an empty bound that
    // refuses everything forever.
    const bound = parseScopeTokens(granted);
    const allowed = bound.length > 0 ? bound : parseScopeTokens(stored);
    if (allowed.length === 0)
        return storedValue;
    // Canonical on every limb, including the ones that keep what is stored: a
    // record whose scope is ragged would otherwise keep that form forever, and
    // a whitespace-only one is truthy enough to be emitted in a 200.
    const keep = canonicalScope(stored);
    // Named but unusable is not silence. The upstream said something about the
    // scope and this route could not read it, so it learned nothing — and
    // nothing is a reason to keep what is stored, never to widen it.
    if (answered.kind === "unusable")
        return keep;
    if (answered.kind === "omitted")
        return allowed.join(" ");
    const asked = parseScopeTokens(answered.value);
    const within = new Set(allowed);
    return asked.every((entry) => within.has(entry)) ? asked.join(" ") : keep;
};
/**
 * Reads a refresh answer's lifetime fields. Every accepted end is capped at
 * `now + maxTokenLifetimeMs`, never refused over it. An answer that names no
 * lifetime (`unstated`; RFC 6749 §5.1 only recommends `expires_in`) is given
 * the maximum, obtained when the call began: a refreshed token is never
 * stored with no finite expiry, which would never be refreshed or capped.
 */
const readRefreshedLifetime = (answer, unreadable, policy) => {
    if (unreadable.has("expiresIn") || unreadable.has("expiresAt")) {
        return { accepted: false, verdict: "unreadable" };
    }
    const now = Date.now();
    const capped = (endMs) => new Date(Math.min(endMs, now + policy.maxTokenLifetimeMs));
    const lifetime = readUpstreamTokenLifetime({ expiresIn: answer.expiresIn, expiresAt: answer.expiresAt }, { calledAt: policy.calledAt, now, floorMs: REFRESH_FLOOR_MS });
    switch (lifetime.verdict) {
        case "unstated":
            return {
                accepted: true,
                expiresAt: capped(Number.POSITIVE_INFINITY),
                obtainedAt: new Date(policy.calledAt),
            };
        case "malformed":
        case "contradictory":
        case "spent":
            return { accepted: false, verdict: lifetime.verdict };
        case "finite":
            return {
                accepted: true,
                expiresAt: capped(lifetime.expiresAt.getTime()),
                obtainedAt: lifetime.stated === "expiresAt" ? undefined : lifetime.obtainedAt,
            };
        default: {
            // A verdict a newer core adds is not one this route can store.
            const unknownVerdict = lifetime;
            void unknownVerdict;
            return { accepted: false, verdict: "unrecognised" };
        }
    }
};
/**
 * Reads `refreshed` once. `currentTokens` is the freshest snapshot of the
 * record, whose type stands when the answer names none.
 */
export const readRefreshAnswer = (refreshed, currentTokens, policy) => {
    // The adapter's answer is unverified third-party data, read field by
    // field behind guards: it may be `null`, a getter may throw, and an
    // exception here would lose the rotated refresh token `recordRefresh`
    // salvages.
    const unreadable = new Set();
    const answer = typeof refreshed === "object" && refreshed !== null
        ? {
            accessToken: readField(refreshed, "accessToken", unreadable),
            refreshToken: readField(refreshed, "refreshToken", unreadable),
            idToken: readField(refreshed, "idToken", unreadable),
            expiresIn: readField(refreshed, "expiresIn", unreadable),
            expiresAt: readField(refreshed, "expiresAt", unreadable),
            scope: readField(refreshed, "scope", unreadable),
            tokenType: readField(refreshed, "tokenType", unreadable),
        }
        : {};
    const lifetime = readRefreshedLifetime(answer, unreadable, policy);
    // The refreshed token's type: unreadable or not a type name is broken
    // (joins the refusals of an unusable answer, as core's `retrieve.mts`
    // does); absent keeps the record's type, since a refresh does not change
    // how tokens are presented; a type name is what the record carries next.
    const namedType = answer.tokenType !== undefined;
    const answeredType = namedType ? canonicalTokenType(answer.tokenType) : undefined;
    const tokenTypeIsBroken = unreadable.has("tokenType") || (namedType && answeredType === undefined);
    // The stored value is carried verbatim: re-reading it through
    // `canonicalTokenType` would turn junk into absence, which reads as
    // Bearer. The disclosure check refuses it instead.
    const nextTokenType = answeredType ?? currentTokens.tokenType;
    const usable = (value) => (isUsableToken(value) ? value : undefined);
    return {
        // No (or an empty) access token is a failed refresh, never a 200
        // without `access_token` (RFC 6749 §5.1).
        accessToken: usable(answer.accessToken),
        // `??` on the raw field would let `""` through, and an empty string
        // overwriting a usable stored token strands the connection.
        rotatedRefreshToken: usable(answer.refreshToken),
        rotatedIdToken: usable(answer.idToken),
        lifetime,
        tokenTypeIsBroken,
        nextTokenType,
        answeredScope: classifyAnsweredScope(answer, unreadable),
    };
};
