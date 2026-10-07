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
 * The one rule from an upstream token answer, a code exchange's or a
 * refresh's, to the access token a grant's credential stores, or the reason
 * it may not be stored. Every writer of a grant's credential reads its answer
 * here.
 *
 * The answer is read once, each field on its own and into plain values;
 * nothing of the adapter's is read or kept after that. A field whose read
 * throws, or that is not what its type says, makes the answer malformed:
 * ineligible, never an outage.
 */
import { parseScopeTokens } from "../federations/scope.mjs";
import { instantOf, readUpstreamTokenLifetime } from "../federations/token-lifetime.mjs";
import { judgeUpstreamAccessToken } from "./eligibility.mjs";
import { federationGrantAccessToken, federationGrantHeldToken, } from "./held-token.mjs";
/** A field whose read threw, or that is an object where a primitive must be. */
const MALFORMED = Symbol("malformed");
/** `answer[key]`, read once; `MALFORMED` when reading it throws (`null` throws too). */
function readField(answer, key) {
    try {
        return answer[key];
    }
    catch {
        return MALFORMED;
    }
}
/** `value`, or `MALFORMED` for an object: no adapter object outlives the snapshot. */
const primitive = (value) => (typeof value === "object" && value !== null) || typeof value === "function"
    ? MALFORMED
    : value;
/** An answered expiry by the instant its Date holds, never by a method it may override. */
function readExpiry(value) {
    if (value === undefined || value === null || value === MALFORMED)
        return value;
    const ms = instantOf(value);
    if (ms !== undefined)
        return ms;
    // Refused either way: whether it is a Date at all only names why.
    try {
        return value instanceof Date ? Number.NaN : MALFORMED;
    }
    catch {
        return MALFORMED;
    }
}
function snapshot(answer) {
    const refreshToken = readField(answer, "refreshToken");
    return {
        refreshToken: typeof refreshToken === "string" && refreshToken !== "" ? refreshToken : undefined,
        accessToken: primitive(readField(answer, "accessToken")),
        tokenType: primitive(readField(answer, "tokenType")),
        expiresIn: primitive(readField(answer, "expiresIn")),
        expiresAt: readExpiry(readField(answer, "expiresAt")),
        scope: primitive(readField(answer, "scope")),
    };
}
/** Epoch ms: when the held token ends; no bound when its dates hold no instant. */
function heldEnd(held) {
    const { obtainedAt, expiresAt } = federationGrantHeldToken(held);
    const end = expiresAt.getTime();
    return Number.isNaN(obtainedAt.getTime()) || Number.isNaN(end) ? Number.POSITIVE_INFINITY : end;
}
/**
 * Reads an upstream token answer once, and judges its access token: eligible,
 * with the token to store, or refused with the ineligibility reason. The
 * refresh token is read whatever else is wrong with the answer.
 *
 * - `token_type` is required (RFC 6749 §5.1): an answer without one is malformed.
 * - The scope is read by RFC 6749 §3.3's grammar (`parseScopeTokens`). Absent
 *   or blank means `requestedScopes`; named but naming no scope-token is
 *   malformed. More than `consentedScopes` is `scope_exceeded`, judged before
 *   the token type.
 * - Only a lifetime both `expiresIn` and `expiresAt` state, with life left at
 *   `receivedAt`, is finite (`readUpstreamTokenLifetime`).
 * - The same access token as `held` ends no later than `held` does: a
 *   re-answer never lengthens a token's life.
 *
 * Throws a `RangeError` only for a clock that is not a finite instant.
 */
export function readFederationGrantUpstreamAnswer(answer, context) {
    const { refreshToken, accessToken, tokenType, expiresIn = null, expiresAt = null, scope, } = snapshot(answer);
    const refused = (reason) => ({
        refreshToken,
        accessToken: { eligible: false, reason },
    });
    const named = parseScopeTokens(scope);
    if (typeof accessToken !== "string" ||
        accessToken === "" ||
        typeof tokenType !== "string" ||
        tokenType === "" ||
        (expiresIn !== null && typeof expiresIn !== "number") ||
        expiresAt === MALFORMED ||
        (scope !== undefined &&
            (typeof scope !== "string" || (named.length === 0 && scope.trim() !== "")))) {
        return refused("malformed_token_response");
    }
    const scopes = named.length === 0 ? [...context.requestedScopes] : [...named];
    const reading = readUpstreamTokenLifetime({ expiresIn, expiresAt: expiresAt === null ? null : new Date(expiresAt) }, { calledAt: context.calledAt, now: context.receivedAt, floorMs: 0 });
    if (reading.verdict !== "finite" || reading.stated !== "both") {
        return refused("no_finite_lifetime");
    }
    const held = context.held;
    const expiresAtMs = Math.min(reading.expiresAt.getTime(), held !== undefined && accessToken === held.value ? heldEnd(held) : Number.POSITIVE_INFINITY);
    if (expiresAtMs <= context.receivedAt)
        return refused("no_finite_lifetime");
    const judgement = judgeUpstreamAccessToken({
        issuedLifetime: reading.issuedLifetime,
        scopes,
        consentedScopes: context.consentedScopes,
        maxAccessTokenLifetime: context.maxAccessTokenLifetime,
        tokenType,
    });
    if (!judgement.eligible)
        return refused(judgement.reason);
    return {
        refreshToken,
        accessToken: {
            eligible: true,
            token: federationGrantAccessToken({ value: accessToken, tokenType, scopes }, { ...reading, expiresAt: new Date(expiresAtMs) }),
        },
    };
}
