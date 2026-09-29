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

import type {
	FederationGrantAuthorization,
	FederationGrantCredentials,
} from "@o3co/auth-provider-core";

/**
 * How a federation grant's authorization and credential are written down.
 *
 * The canonical authorization text is stored in the grant HASH and is what the
 * credential's authenticated data is computed from, so one authorization must
 * produce the same bytes in every process, replica and restart. Hence arrays,
 * not objects (key order is an encoder's choice); every instant as a decimal
 * millisecond string (a JSON number is a formatting decision: `1e21`, `-0`);
 * JSON escaping rather than a separator one field's content could move; and
 * no tidying: scopes are neither sorted nor deduplicated and strings are not
 * normalized, because what the upstream granted is the record and a tamper
 * test that cannot see a reordering is not one.
 *
 * The text is never decoded and re-encoded on the way to the authenticated
 * data: the bytes the HASH holds are the bytes that are authenticated. So no
 * Lua script may re-encode it or write anything derived from a decode of it
 * back to the record. A read-only decode is fine: `LUA_FG_REVOKE` reads the
 * expiry out of it for the horizon it honours, and writes nothing it read.
 */

/** The instant as the format writes it: a decimal millisecond string. */
const ms = (value: Date): string => String(value.getTime());

const dateFrom = (value: unknown): Date | undefined => {
	if (typeof value !== "string" || !/^-?\d+$/.test(value)) return undefined;
	const at = new Date(Number(value));
	return Number.isNaN(at.getTime()) ? undefined : at;
};

const stringFrom = (value: unknown): string | undefined =>
	typeof value === "string" ? value : undefined;

const scopesFrom = (value: unknown): readonly string[] | undefined =>
	Array.isArray(value) && value.every((entry) => typeof entry === "string")
		? (value as string[])
		: undefined;

/** An optional field: `[]` when absent, `[value]` when present — so that absent and empty are different bytes. */
const optional = (value: string | undefined): readonly string[] =>
	value === undefined ? [] : [value];

const optionalFrom = (value: unknown): { present: false } | { present: true; value?: string } => {
	if (!Array.isArray(value) || value.length > 1) return { present: false };
	if (value.length === 0) return { present: true };
	const only = stringFrom(value[0]);
	return only === undefined ? { present: false } : { present: true, value: only };
};

/**
 * The text stored under the HASH's `authorization` field, and the last
 * element of {@link credentialAad}.
 */
export function canonicalAuthorization(authorization: FederationGrantAuthorization): string {
	return JSON.stringify([
		authorization.identityRevision,
		authorization.authorizationRevision,
		authorization.upstream.issuer,
		authorization.upstream.subject,
		optional(authorization.resource),
		authorization.scopes,
		ms(authorization.consent.at),
		authorization.consent.sid,
		authorization.consent.scopes,
		ms(authorization.authorizedAt),
		ms(authorization.expiresAt),
	]);
}

/**
 * Inverse of {@link canonicalAuthorization}. `undefined` for anything that is
 * not that shape: a HASH whose authorization cannot be read is a record that
 * answers nothing, and guessing at a field would authenticate a credential
 * against something the upstream never granted.
 */
export function parseCanonicalAuthorization(
	text: string,
): FederationGrantAuthorization | undefined {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!Array.isArray(parsed) || parsed.length !== 11) return undefined;
	const identityRevision = stringFrom(parsed[0]);
	const authorizationRevision = stringFrom(parsed[1]);
	const issuer = stringFrom(parsed[2]);
	const subject = stringFrom(parsed[3]);
	const resource = optionalFrom(parsed[4]);
	const scopes = scopesFrom(parsed[5]);
	const consentAt = dateFrom(parsed[6]);
	const sid = stringFrom(parsed[7]);
	const consentScopes = scopesFrom(parsed[8]);
	const authorizedAt = dateFrom(parsed[9]);
	const expiresAt = dateFrom(parsed[10]);
	if (
		identityRevision === undefined ||
		authorizationRevision === undefined ||
		issuer === undefined ||
		subject === undefined ||
		!resource.present ||
		scopes === undefined ||
		consentAt === undefined ||
		sid === undefined ||
		consentScopes === undefined ||
		authorizedAt === undefined ||
		expiresAt === undefined
	) {
		return undefined;
	}
	return {
		identityRevision,
		authorizationRevision,
		upstream: { issuer, subject },
		resource: resource.value,
		scopes,
		consent: { at: consentAt, sid, scopes: consentScopes },
		authorizedAt,
		expiresAt,
	};
}

export interface FederationGrantCredentialBinding {
	/** The complete Redis key the ciphertext is stored under. */
	readonly credentialKey: string;
	readonly id: string;
	readonly subject: string;
	readonly clientId: string;
	readonly connection: string;
	/** Exactly the bytes the HASH holds — never re-serialized from a parsed record. */
	readonly authorization: string;
}

/**
 * The authenticated data a credential is sealed under: the key it lives at,
 * the record's identity, and every field of the authorization.
 *
 * The key name binds the ciphertext to its key, so a credential copied to
 * another grant's key does not read as that grant's. The authorization is
 * included because the binding is a plaintext HASH: a Redis writer or a
 * mismatched restore could otherwise re-point `clientId`, extend `expiresAt`,
 * move `consent.at` past a revocation watermark, or rewrite
 * `authorizationRevision` to skip a renewed consent, all without touching the
 * ciphertext. A tampered field fails authentication and the record reads as
 * unreadable. The usage fields (`lastUsedAt`, the ineligibility marker, a
 * failed refresh's stamp) change while the grant is in use and decide nothing
 * it allows, so they are outside it.
 * See ADR 2026-09-17-federation-grants-offline-delegation, D16.
 */
export function credentialAad(binding: FederationGrantCredentialBinding): Buffer {
	return Buffer.from(
		JSON.stringify([
			"o3co.auth-provider.federation-grant",
			1,
			binding.credentialKey,
			binding.id,
			binding.subject,
			binding.clientId,
			binding.connection,
			binding.authorization,
		]),
		"utf8",
	);
}

/** The plaintext inside the envelope. An array, for the reasons {@link canonicalAuthorization} is one. */
export function encodeCredentials(credentials: FederationGrantCredentials): string {
	const access = credentials.accessToken;
	return JSON.stringify([
		1,
		credentials.refreshToken,
		access === undefined
			? []
			: [
					[
						access.value,
						access.tokenType,
						ms(access.obtainedAt),
						String(access.issuedLifetime),
						access.scopes,
					],
				],
	]);
}

const lifetimeFrom = (value: unknown): number | undefined => {
	if (typeof value !== "string" || value.length === 0) return undefined;
	const seconds = Number(value);
	return Number.isFinite(seconds) ? seconds : undefined;
};

/** Inverse of {@link encodeCredentials}; `undefined` for anything else, which reads as an unreadable credential. */
export function decodeCredentials(text: string): FederationGrantCredentials | undefined {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return undefined;
	}
	if (!Array.isArray(parsed) || parsed.length !== 3 || parsed[0] !== 1) return undefined;
	const refreshToken = stringFrom(parsed[1]);
	if (refreshToken === undefined || refreshToken.length === 0) return undefined;
	if (!Array.isArray(parsed[2]) || parsed[2].length > 1) return undefined;
	if (parsed[2].length === 0) return { refreshToken, accessToken: undefined };
	const token: unknown = parsed[2][0];
	if (!Array.isArray(token) || token.length !== 5) return undefined;
	const value = stringFrom(token[0]);
	const tokenType = stringFrom(token[1]);
	const obtainedAt = dateFrom(token[2]);
	const issuedLifetime = lifetimeFrom(token[3]);
	const scopes = scopesFrom(token[4]);
	if (
		value === undefined ||
		tokenType === undefined ||
		obtainedAt === undefined ||
		issuedLifetime === undefined ||
		scopes === undefined
	) {
		return undefined;
	}
	return { refreshToken, accessToken: { value, tokenType, obtainedAt, issuedLifetime, scopes } };
}
