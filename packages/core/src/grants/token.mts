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
import { randomUUID } from "node:crypto";
import type { JWTPayload, KeyStore } from "../keys/KeyStore.mjs";
import type { Confirmation } from "./confirmation.mjs";
import { BINDING_PROFILES, CONFIRMATION_MEMBERS } from "./confirmationMatch.mjs";

export const formatObject = <T extends object>(data: T): Partial<T> => {
	return Object.fromEntries(
		Object.entries(data).filter(([, v]) => v !== undefined && v !== null),
	) as Partial<T>;
};

export interface Token {
	token: string;
	expiresIn?: number;
	subject?: string;
	scope?: string;
	tokenType?: "at+jwt" | "rt+jwt";
	audience?: string;
	issuer?: string;
	/**
	 * Echo of `GenerateTokenOptions.confirmation` when set. It does NOT drive
	 * claim emission — that is `GenerateTokenOptions.confirmation`'s job — but
	 * on an access token it is what `generateTokenResponse` reads the
	 * response's `token_type` from, so the envelope describes the `cnf` the
	 * token carries. See RFC 7800 §3 for the `cnf` claim structure and Wave 2
	 * Token-binding Cluster spec §4.4 for the field's role here.
	 */
	readonly confirmation?: Confirmation;
}

export interface IntermediateToken {
	accessToken: Token;
	refreshToken?: Token;
	idToken?: Token;
}

export interface TokenResponse {
	access_token: string;
	token_type: string;
	scope?: string;
	refresh_token?: string | null;
	expires_in?: number;
	id_token?: string;
}

/**
 * The wire-level `token_type` for an access token bound by `confirmation`:
 * the scheme core's binding profile names for the member it carries —
 * `DPoP` for `cnf.jkt` (RFC 9449 §5), `Bearer` for `cnf["x5t#S256"]`, which
 * RFC 8705 §3 leaves on the bearer scheme — and `Bearer` for an unbound one.
 */
const tokenTypeFor = (confirmation: Confirmation | undefined): "Bearer" | "DPoP" => {
	const member = CONFIRMATION_MEMBERS.find(
		(candidate) => confirmation !== undefined && candidate in confirmation,
	);
	return member === undefined ? "Bearer" : BINDING_PROFILES[member].challenge;
};

/**
 * The RFC 6749 §5.1 token response for the tokens a grant minted.
 *
 * `token_type` is read off the access token's own confirmation (the echo
 * `generateToken` puts on the `Token`), not handed in: a grant that forgot to
 * say `DPoP` advertised a `cnf.jkt` token as Bearer, and a DPoP-aware client
 * believed the envelope and presented it as one — which RFC 9449 §7.1 has a
 * resource server refuse. Read off the token, the envelope cannot disagree
 * with the claim.
 */
export const generateTokenResponse = ({
	accessToken,
	refreshToken = undefined,
	idToken = undefined,
}: IntermediateToken): TokenResponse => {
	return {
		access_token: accessToken.token,
		token_type: tokenTypeFor(accessToken.confirmation),
		...formatObject({
			scope: accessToken.scope,
			refresh_token: refreshToken ? refreshToken.token : null,
			expires_in: accessToken.expiresIn,
			id_token: idToken ? idToken.token : undefined,
		}),
	};
};

export interface GenerateTokenOptions {
	/**
	 * Seconds from `iat` to `exp`: a positive whole number, or absent for a
	 * token with no `exp`. Anything else — a fraction, NaN, Infinity, zero or
	 * less, or past `Number.MAX_SAFE_INTEGER` — is a `RangeError` before
	 * anything is signed, and so is a lifetime whose `exp` (`iat + expiresIn`)
	 * would pass `Number.MAX_SAFE_INTEGER`.
	 */
	expiresIn?: number;
	keyStore: KeyStore;
	issuer?: string | null;
	audience?: string | null;
	subject?: string | null;
	authorizedParty?: string | null;
	scope?: string | null;
	tokenType?: "at+jwt" | "rt+jwt";
	/**
	 * RFC 7800 confirmation claim to emit as the `cnf` JWT claim. When
	 * absent, no `cnf` claim is emitted — the issued token is unbound
	 * (Bearer semantics).
	 */
	confirmation?: Confirmation;
	/**
	 * The token's `jti`. A fresh UUID unless the caller supplies one — which
	 * it does when the token's identity has to be reserved somewhere before
	 * it is signed (#449): the refresh grant commits the rotation to the
	 * family store first and signs only once the reservation holds, so a
	 * lost race costs no signature.
	 */
	readonly jti?: string;
	/**
	 * Epoch seconds for `iat`, and what `exp` is measured from. The clock
	 * unless the caller supplies it — supplied alongside `jti` so the
	 * expiry that was reserved is exactly the expiry that is signed.
	 */
	readonly issuedAt?: number;
}

export const generateToken = async (
	data: object,
	{
		expiresIn = undefined,
		keyStore,
		issuer = null,
		audience = null,
		subject = null,
		authorizedParty = null,
		scope = null,
		tokenType = undefined,
		confirmation = undefined,
		jti = randomUUID(),
		issuedAt = undefined,
	}: GenerateTokenOptions,
): Promise<Token> => {
	// Both are reservations made before signing (#449). An empty `jti` would
	// sign a token with no identity for every replay check keyed on it; an
	// `issuedAt` that is not whole epoch seconds would sign `iat` / `exp` no
	// verifier reads as intended.
	if (jti.length === 0) throw new Error("generateToken: jti must not be empty");
	if (issuedAt !== undefined && !(Number.isSafeInteger(issuedAt) && issuedAt >= 0)) {
		throw new Error("generateToken: issuedAt must be a non-negative whole number of epoch seconds");
	}
	// `exp` is `iat + expiresIn`, so the lifetime has to be whole seconds too:
	// a fraction signs a fractional `exp` each verifier rounds its own way,
	// NaN and Infinity serialise as `"exp": null`, and zero or less signs a
	// token that is dead on arrival. The configuration schema refuses all of
	// these; a caller that computes or hand-builds its lifetime meets this.
	if (expiresIn !== undefined && !(Number.isSafeInteger(expiresIn) && expiresIn > 0)) {
		throw new RangeError(
			`generateToken: expiresIn must be a positive whole number of seconds (got ${String(expiresIn)})`,
		);
	}
	const now = issuedAt ?? Math.floor(Date.now() / 1000);
	// Both operands are safe integers now; their sum need not be. Past 2^53
	// `iat + expiresIn` is rounded to a neighbouring integer, so two lifetimes
	// would sign the same `exp`. The configuration caps a lifetime at a year,
	// far below this; a caller that computes one does not have that cap.
	if (expiresIn !== undefined && !Number.isSafeInteger(now + expiresIn)) {
		throw new RangeError(
			`generateToken: exp (iat ${now} + expiresIn ${expiresIn}) is past Number.MAX_SAFE_INTEGER`,
		);
	}
	const claims: JWTPayload = {
		...(data as Record<string, unknown>),
		...(authorizedParty ? { azp: authorizedParty } : {}),
		...(scope ? { scope } : {}),
		iat: now,
		jti,
		...(expiresIn !== undefined ? { exp: now + expiresIn } : {}),
		...(issuer != null ? { iss: issuer } : {}),
		...(audience != null ? { aud: audience } : {}),
		...(subject != null ? { sub: subject } : {}),
		...(confirmation ? { cnf: confirmation } : {}),
	};

	const token = await keyStore.sign({
		claims,
		...(tokenType ? { header: { typ: tokenType } } : {}),
	});

	// Construct Token via spread so `readonly` fields (currently
	// `confirmation`) can be assigned at construction without a cast.
	// Spec §4.4 marks `Token.confirmation` readonly for caller-side
	// immutability; building the record in one expression honors that
	// contract without diverging from the existing per-field guards.
	return {
		token,
		...(expiresIn !== undefined ? { expiresIn } : {}),
		...(audience !== null && audience !== undefined ? { audience } : {}),
		...(issuer !== null && issuer !== undefined ? { issuer } : {}),
		...(subject !== null && subject !== undefined ? { subject } : {}),
		...(scope !== null && scope !== undefined ? { scope } : {}),
		...(tokenType !== undefined ? { tokenType } : {}),
		...(confirmation !== undefined ? { confirmation } : {}),
	};
};
