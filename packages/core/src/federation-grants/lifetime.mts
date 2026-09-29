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

import type { FederationGrantExpiredReason } from "./types.mjs";

/**
 * The longest a federation grant can live: one year.
 *
 * The schema caps `federationGrants.maxExpiresIn` at the same value, but a
 * hand-built config bypasses the schema, and the revocation boundary is
 * retained for exactly this long. So it is a domain constant, checked both
 * when an intent's lifetime is resolved and when a grant is activated.
 */
export const FEDERATION_GRANT_LIFETIME_CEILING_MS = 31_536_000_000;

function assertPositiveFinite(name: string, value: number): void {
	if (!Number.isFinite(value) || value <= 0) {
		throw new RangeError(`${name} must be a positive finite number of milliseconds`);
	}
}

/**
 * The lifetime a grant gets when its intent is lodged. Requests and the
 * default are clamped (not rejected) to the maximum and the ceiling; the
 * response tells the caller what applied. Clamped here, not only at
 * `activate`, so a user is never asked to consent to a lifetime the write
 * would refuse.
 */
export function resolveFederationGrantLifetimeMs(limits: {
	readonly requestedMs?: number;
	readonly defaultMs: number;
	readonly maxMs: number;
}): number {
	assertPositiveFinite("defaultMs", limits.defaultMs);
	assertPositiveFinite("maxMs", limits.maxMs);
	if (limits.requestedMs !== undefined) assertPositiveFinite("requestedMs", limits.requestedMs);
	return Math.min(
		limits.requestedMs ?? limits.defaultMs,
		limits.maxMs,
		FEDERATION_GRANT_LIFETIME_CEILING_MS,
	);
}

/**
 * A grant's expiry counts from the consent, not from the callback that
 * follows it by up to ten minutes. The guarantee that no grant outlives its
 * revocation boundary rests on `expiresAt − consent.at` being within the
 * ceiling, so both are measured from the same instant.
 */
export function federationGrantExpiresAt(consentAt: Date, lifetimeMs: number): Date {
	return new Date(consentAt.getTime() + lifetimeMs);
}

/**
 * The guard `activate` applies to the fields it is about to write. A date
 * that is not a date fails it: `NaN > 0` is false.
 */
export function withinFederationGrantLifetimeCeiling(consentAt: Date, expiresAt: Date): boolean {
	const lifetime = expiresAt.getTime() - consentAt.getTime();
	return lifetime > 0 && lifetime <= FEDERATION_GRANT_LIFETIME_CEILING_MS;
}

interface ExpiryFields {
	readonly consent: { readonly at: Date };
	readonly expiresAt: Date;
}

/**
 * When a grant stops yielding tokens: the consented expiry, or the operator's
 * current maximum counted from the consent, whichever comes first. Lowering
 * the maximum shortens existing grants, which is what lowering it means.
 *
 * Nothing that is persisted — a key's TTL, the revocation boundary — may be
 * computed from this. A maximum that can be raised again cannot be the basis
 * of a guarantee; persisted horizons use the stored `expiresAt` or the ceiling.
 */
export function federationGrantEffectiveExpiry(grant: ExpiryFields, maxMs: number): Date {
	return new Date(Math.min(grant.expiresAt.getTime(), grant.consent.at.getTime() + maxMs));
}

/**
 * Whether a grant has expired, and which bound ended it. The consented
 * lifetime is terminal; the operator's maximum is not (raising it revives
 * the grant, within the consent). When both have passed, the terminal
 * reason is reported.
 *
 * Each test is "still before the bound?" negated, so a NaN date or maximum
 * reads as expired rather than live for ever.
 */
export function federationGrantExpiryState(
	grant: ExpiryFields,
	now: Date,
	maxMs: number,
): "live" | FederationGrantExpiredReason {
	if (!(now.getTime() < grant.expiresAt.getTime())) return "consented_lifetime";
	if (!(now.getTime() < grant.consent.at.getTime() + maxMs)) return "operator_maximum";
	return "live";
}
