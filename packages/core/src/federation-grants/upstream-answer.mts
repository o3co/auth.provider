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
import type { DelegatedTokens } from "../federations/types.mjs";
import { judgeUpstreamAccessToken } from "./eligibility.mjs";
import { federationGrantAccessToken, type WrittenAccessToken } from "./held-token.mjs";
import type { FederationGrantIneligibilityReason } from "./types.mjs";

export interface FederationGrantUpstreamAnswerContext {
	/** Epoch ms: when the upstream was asked. A finite lifetime is dated from here. */
	readonly calledAt: number;
	/** Epoch ms: when its answer arrived. A token with no life left by then is refused. */
	readonly receivedAt: number;
	/** What an answer that names no scope carries: what the request asked for (RFC 6749 §5.1). */
	readonly requestedScopes: readonly string[];
	/** What the user consented to: a token that carries more is refused as `scope_exceeded`. */
	readonly consentedScopes: readonly string[];
	/** Seconds: the connection's current maximum. */
	readonly maxAccessTokenLifetime: number;
}

export interface FederationGrantUpstreamAnswer {
	/** `undefined` when the answer carries none that is a non-empty string, or its read threw. */
	readonly refreshToken: string | undefined;
	readonly accessToken:
		| { readonly eligible: true; readonly token: WrittenAccessToken }
		| { readonly eligible: false; readonly reason: FederationGrantIneligibilityReason };
}

/** A field whose read threw, or that is an object where a primitive must be. */
const MALFORMED = Symbol("malformed");

type Primitive = string | number | bigint | boolean | symbol | null | undefined;

/** The answer, each field read exactly once and reduced to primitives. */
interface AnswerSnapshot {
	readonly refreshToken: string | undefined;
	readonly accessToken: Primitive;
	readonly tokenType: Primitive;
	readonly expiresIn: Primitive;
	/** Epoch ms; `NaN` for a Date that holds no instant. */
	readonly expiresAt: number | null | undefined | typeof MALFORMED;
	readonly scope: Primitive;
}

/** `answer[key]`, read once; `MALFORMED` when reading it throws (`null` throws too). */
function readField(answer: unknown, key: keyof DelegatedTokens): unknown {
	try {
		return (answer as Record<string, unknown>)[key];
	} catch {
		return MALFORMED;
	}
}

/** `value`, or `MALFORMED` for an object: no adapter object outlives the snapshot. */
const primitive = (value: unknown): Primitive =>
	(typeof value === "object" && value !== null) || typeof value === "function"
		? MALFORMED
		: (value as Primitive);

/** An answered expiry by the instant its Date holds, never by a method it may override. */
function readExpiry(value: unknown): AnswerSnapshot["expiresAt"] {
	if (value === undefined || value === null || value === MALFORMED) return value;
	const ms = instantOf(value);
	if (ms !== undefined) return ms;
	// Refused either way: whether it is a Date at all only names why.
	try {
		return value instanceof Date ? Number.NaN : MALFORMED;
	} catch {
		return MALFORMED;
	}
}

function snapshot(answer: unknown): AnswerSnapshot {
	const refreshToken = readField(answer, "refreshToken");
	return {
		refreshToken:
			typeof refreshToken === "string" && refreshToken !== "" ? refreshToken : undefined,
		accessToken: primitive(readField(answer, "accessToken")),
		tokenType: primitive(readField(answer, "tokenType")),
		expiresIn: primitive(readField(answer, "expiresIn")),
		expiresAt: readExpiry(readField(answer, "expiresAt")),
		scope: primitive(readField(answer, "scope")),
	};
}

/**
 * Reads an upstream token answer once, and judges its access token: eligible,
 * with the token to store, or refused with the ineligibility reason. The
 * refresh token is read whatever else is wrong with the answer.
 *
 * - `token_type` is required (RFC 6749 §5.1): an answer without one is malformed.
 * - The scope is read by RFC 6749 §3.3's grammar (`parseScopeTokens`). Absent
 *   means `requestedScopes`; named but naming no scope-token, blank included,
 *   is malformed. More than `consentedScopes` is `scope_exceeded`.
 * - Only a lifetime both `expiresIn` and `expiresAt` state, with life left at
 *   `receivedAt`, is finite (`readUpstreamTokenLifetime`).
 *
 * Throws a `RangeError` only for a clock that is not a finite instant.
 */
export function readFederationGrantUpstreamAnswer(
	answer: unknown,
	context: FederationGrantUpstreamAnswerContext,
): FederationGrantUpstreamAnswer {
	const {
		refreshToken,
		accessToken,
		tokenType,
		expiresIn = null,
		expiresAt = null,
		scope,
	} = snapshot(answer);
	const refused = (reason: FederationGrantIneligibilityReason): FederationGrantUpstreamAnswer => ({
		refreshToken,
		accessToken: { eligible: false, reason },
	});
	const named = parseScopeTokens(scope);
	if (
		typeof accessToken !== "string" ||
		accessToken === "" ||
		typeof tokenType !== "string" ||
		tokenType === "" ||
		(expiresIn !== null && typeof expiresIn !== "number") ||
		expiresAt === MALFORMED ||
		(scope !== undefined && (typeof scope !== "string" || named.length === 0))
	) {
		return refused("malformed_token_response");
	}
	const scopes = scope === undefined ? [...context.requestedScopes] : [...named];

	const reading = readUpstreamTokenLifetime(
		{ expiresIn, expiresAt: expiresAt === null ? null : new Date(expiresAt) },
		{ calledAt: context.calledAt, now: context.receivedAt, floorMs: 0 },
	);
	if (reading.verdict !== "finite" || reading.stated !== "both") {
		return refused("no_finite_lifetime");
	}
	const judgement = judgeUpstreamAccessToken({
		issuedLifetime: reading.issuedLifetime,
		scopes,
		consentedScopes: context.consentedScopes,
		maxAccessTokenLifetime: context.maxAccessTokenLifetime,
		tokenType,
	});
	if (!judgement.eligible) return refused(judgement.reason);
	return {
		refreshToken,
		accessToken: {
			eligible: true,
			token: federationGrantAccessToken({ value: accessToken, tokenType, scopes }, reading),
		},
	};
}
