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

import {
	canonicalScope,
	canonicalTokenType,
	type FederationTokens,
	parseScopeTokens,
	type RefreshedTokens,
	readUpstreamTokenLifetime,
} from "@o3co/auth-provider-core";
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
 * token. `unreadable` records which, because for a lifetime field "absent"
 * means no finite expiry (never refresh), and a throwing getter must not
 * collapse into that.
 */
const readField = <T,>(source: object, key: string, unreadable: Set<string>): T | undefined => {
	try {
		return (source as Record<string, unknown>)[key] as T | undefined;
	} catch {
		unreadable.add(key);
		return undefined;
	}
};

/**
 * How a refresh answer names the token's scope. `narrowedScope` bounds it by
 * `granted`, what the user consented to at link time: RFC 6749 §6 bounds a
 * refresh by the original grant, not by the token it replaces, so judging
 * against the current scope would make a narrowing permanent. A record
 * without `granted` is judged against its current scope.
 *
 * - narrower than the bound: recorded (§6 allows narrowing);
 * - named but unusable: the stored value stands — learning nothing is never
 *   a reason to widen;
 * - omitted: the bound itself — no `scope` is sent upstream, and §5.1 lets
 *   the answer omit it only when it matches the request, i.e. the grant;
 * - wider than the bound: not recorded; the stored value stands (§6).
 *
 * Reading silence as the bound can over-report after an upstream narrows,
 * but never beyond consent, and no authorization decision here reads the
 * field. Answers are canonical. The sibling rule for grants that outlive a
 * session is core's `scopesWithin` / `consentedScopes`.
 */
type AnsweredScope =
	/** The upstream named no scope at all. */
	| { readonly kind: "omitted" }
	/** It named one, and it parses. */
	| { readonly kind: "named"; readonly value: string }
	/** It named something this route could not use: unreadable, or not a scope. */
	| { readonly kind: "unusable" };

/**
 * Which reading an answer is. A getter that threw (`readField` → `undefined`)
 * is unusable, not omitted: omitted means the full grant, so collapsing the
 * two would let an adapter widen the scope by failing to be read.
 */
const classifyAnsweredScope = (
	answer: Partial<RefreshedTokens>,
	unreadable: ReadonlySet<string>,
): AnsweredScope => {
	if (unreadable.has("scope")) return { kind: "unusable" };
	if (answer.scope === undefined) return { kind: "omitted" };
	const named = parseScopeTokens(answer.scope);
	return named.length > 0 ? { kind: "named", value: named.join(" ") } : { kind: "unusable" };
};

export const narrowedScope = (
	answered: AnsweredScope,
	stored: string | undefined,
	granted: string | undefined,
): string | undefined => {
	const storedValue = typeof stored === "string" ? stored : undefined;
	// The ceiling has to satisfy the same rule as the answer: a `granted` that
	// parses to nothing names no scope, whatever its characters, so it falls
	// through to the current scope rather than standing as an empty bound that
	// refuses everything forever.
	const bound = parseScopeTokens(granted);
	const allowed = bound.length > 0 ? bound : parseScopeTokens(stored);
	if (allowed.length === 0) return storedValue;
	// Canonical on every limb, including the ones that keep what is stored: a
	// record whose scope is ragged would otherwise keep that form forever, and
	// a whitespace-only one is truthy enough to be emitted in a 200.
	const keep = canonicalScope(stored);

	// Named but unusable is not silence. The upstream said something about the
	// scope and this route could not read it, so it learned nothing — and
	// nothing is a reason to keep what is stored, never to widen it.
	if (answered.kind === "unusable") return keep;
	if (answered.kind === "omitted") return allowed.join(" ");

	const asked = parseScopeTokens(answered.value);
	const within = new Set(allowed);
	return asked.every((entry) => within.has(entry)) ? asked.join(" ") : keep;
};

/**
 * A refresh answer as `readRefreshAnswer` read it, and how it judged it. Every
 * verdict on the answer is here, so the code that acts on it judges nothing.
 */
export interface RefreshReading {
	/** The answered access token when it is usable; `undefined` is a failed refresh. */
	readonly accessToken: string | undefined;
	/** The answered refresh token when it is usable, whether or not it differs from the stored one. */
	readonly rotatedRefreshToken: string | undefined;
	/** The answered id token when it is usable. */
	readonly rotatedIdToken: string | undefined;
	/** When the record's token ends next: the derived end, capped at the maximum; `null` is no finite expiry. */
	readonly derivedExpiry: Date | null;
	/**
	 * When the token's lifetime counts from: the start of the refresh call.
	 * `undefined` with no finite expiry, or a broken lifetime. With the cap,
	 * `derivedExpiry − obtainedAt` may exceed the maximum by the call's duration.
	 */
	readonly obtainedAt: Date | undefined;
	readonly lifetimeIsBroken: boolean;
	readonly tokenTypeIsBroken: boolean;
	/** The type the record carries next. */
	readonly nextTokenType: string | undefined;
	/** How the answer named the scope, for `narrowedScope`. */
	readonly answeredScope: AnsweredScope;
}

/** What the route asks of a refresh answer's lifetime. */
export interface RefreshLifetimePolicy {
	/** When the refresh was asked for (epoch ms): an `expiresIn` counts from it. */
	readonly calledAt: number;
	/** The longest a refreshed token is stored for (ms), counted from when the answer is read. */
	readonly maxTokenLifetimeMs: number;
}

/** The lifetime a refresh answer gives the record. */
interface RefreshedLifetime {
	readonly expiresAt: Date | null;
	readonly obtainedAt: Date | undefined;
}

/**
 * The lifetime a refresh answer's fields give the record: `expiresAt: null`
 * when neither names a lifetime (never refresh), `undefined` when they name
 * none that can be used. A finite end is capped at `now + maxTokenLifetimeMs`,
 * never refused over it, and is obtained at core's reading's `obtainedAt`.
 */
const readRefreshedLifetime = (
	answer: Partial<RefreshedTokens>,
	unreadable: ReadonlySet<string>,
	policy: RefreshLifetimePolicy,
): RefreshedLifetime | undefined => {
	// A lifetime field that would not be read is broken, not absent: absent
	// is the never-refresh sentinel.
	if (unreadable.has("expiresIn") || unreadable.has("expiresAt")) return undefined;
	const now = Date.now();
	const lifetime = readUpstreamTokenLifetime(
		{ expiresIn: answer.expiresIn, expiresAt: answer.expiresAt },
		{ calledAt: policy.calledAt, now, floorMs: REFRESH_FLOOR_MS },
	);
	switch (lifetime.verdict) {
		case "unstated":
			return { expiresAt: null, obtainedAt: undefined };
		case "malformed":
		case "contradictory":
		case "spent":
			return undefined;
		case "finite":
			return {
				expiresAt: new Date(
					Math.min(lifetime.expiresAt.getTime(), now + policy.maxTokenLifetimeMs),
				),
				obtainedAt: lifetime.obtainedAt,
			};
		default: {
			// A verdict a newer core adds is not one this route can store.
			const unknownVerdict: never = lifetime;
			void unknownVerdict;
			return undefined;
		}
	}
};

/**
 * Reads `refreshed` once. `currentTokens` is the freshest snapshot of the
 * record, whose type stands when the answer names none.
 */
export const readRefreshAnswer = (
	refreshed: RefreshedTokens,
	currentTokens: FederationTokens,
	policy: RefreshLifetimePolicy,
): RefreshReading => {
	// The adapter's answer is unverified third-party data, read field by
	// field behind guards: it may be `null`, a getter may throw, and an
	// exception here would lose the rotated refresh token `recordRefresh`
	// salvages.
	const unreadable = new Set<string>();
	const answer: Partial<RefreshedTokens> =
		typeof refreshed === "object" && refreshed !== null
			? {
					accessToken: readField<string>(refreshed, "accessToken", unreadable),
					refreshToken: readField<string>(refreshed, "refreshToken", unreadable),
					idToken: readField<string>(refreshed, "idToken", unreadable),
					expiresIn: readField<number | null>(refreshed, "expiresIn", unreadable),
					expiresAt: readField<Date | null>(refreshed, "expiresAt", unreadable),
					scope: readField<string>(refreshed, "scope", unreadable),
					tokenType: readField<string>(refreshed, "tokenType", unreadable),
				}
			: {};

	// A lifetime stated wrongly is not one never stated: `null` is stored as
	// "no finite expiry" (never refresh), so a broken lifetime must not fall
	// through to it.
	const lifetime = readRefreshedLifetime(answer, unreadable, policy);

	// The refreshed token's type: unreadable or not a type name is broken
	// (joins the refusals of an unusable answer, as core's `retrieve.mts`
	// does); absent keeps the record's type, since a refresh does not change
	// how tokens are presented; a type name is what the record carries next.
	const namedType = answer.tokenType !== undefined;
	const answeredType = namedType ? canonicalTokenType(answer.tokenType) : undefined;
	const tokenTypeIsBroken =
		unreadable.has("tokenType") || (namedType && answeredType === undefined);
	// The stored value is carried verbatim: re-reading it through
	// `canonicalTokenType` would turn junk into absence, which reads as
	// Bearer. The disclosure check refuses it instead.
	const nextTokenType = answeredType ?? currentTokens.tokenType;

	const usable = (value: unknown): string | undefined => (isUsableToken(value) ? value : undefined);
	return {
		// No (or an empty) access token is a failed refresh, never a 200
		// without `access_token` (RFC 6749 §5.1).
		accessToken: usable(answer.accessToken),
		// `??` on the raw field would let `""` through, and an empty string
		// overwriting a usable stored token strands the connection.
		rotatedRefreshToken: usable(answer.refreshToken),
		rotatedIdToken: usable(answer.idToken),
		derivedExpiry: lifetime?.expiresAt ?? null,
		obtainedAt: lifetime?.obtainedAt,
		lifetimeIsBroken: lifetime === undefined,
		tokenTypeIsBroken,
		nextTokenType,
		answeredScope: classifyAnsweredScope(answer, unreadable),
	};
};
