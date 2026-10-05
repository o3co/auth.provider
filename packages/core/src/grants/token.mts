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
import { tokenTypeForConfirmation } from "./confirmationMatch.mjs";

export const formatObject = <T extends object>(data: T): Partial<T> => {
	return Object.fromEntries(
		Object.entries(data).filter(([, v]) => v !== undefined && v !== null),
	) as Partial<T>;
};

export interface Token {
	token: string;
	/** The lifetime the token was signed with, in seconds from its `iat`. */
	expiresIn?: number;
	/**
	 * The token's `exp`, in epoch seconds, as `generateToken` signed it. Absent
	 * for a token with no `exp`, or one built by hand.
	 */
	readonly expiresAt?: number;
	subject?: string;
	scope?: string;
	tokenType?: "at+jwt" | "rt+jwt";
	audience?: string;
	issuer?: string;
	/**
	 * Echo of `GenerateTokenOptions.confirmation` (the RFC 7800 §3 `cnf`). It
	 * does not drive claim emission; `generateTokenResponse` reads an access
	 * token's `token_type` from it.
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
 * The RFC 6749 §5.1 token response for the tokens a grant minted.
 *
 * `expires_in` is the access token's time left when the response is built:
 * `max(0, min(expiresIn, expiresAt − floor(now)))` when the token carries
 * `expiresAt`, else `expiresIn` as given. Never above the lifetime, even on a
 * clock that stepped back. A lifetime that ran out while the request was
 * handled answers `0` (the floor), not a negative number: every reader
 * refuses that token by its `exp`, and the client asks again.
 *
 * `token_type` is read off the access token's own confirmation, not handed
 * in, so the envelope cannot disagree with the `cnf` claim: a `cnf.jkt` token
 * advertised as Bearer gets presented as one, and RFC 9449 §7.1 has the
 * resource server refuse it.
 */
export const generateTokenResponse = ({
	accessToken,
	refreshToken = undefined,
	idToken = undefined,
}: IntermediateToken): TokenResponse => {
	return {
		access_token: accessToken.token,
		// `DPoP` for `cnf.jkt`, `Bearer` otherwise — core's one reading of it.
		token_type: tokenTypeForConfirmation(accessToken.confirmation),
		...formatObject({
			scope: accessToken.scope,
			refresh_token: refreshToken ? refreshToken.token : null,
			expires_in: secondsLeft(accessToken),
			id_token: idToken ? idToken.token : undefined,
		}),
	};
};

/** See {@link generateTokenResponse}: the access token's time left, in whole seconds. */
const secondsLeft = ({ expiresIn, expiresAt }: Token): number | undefined => {
	if (expiresIn === undefined || expiresAt === undefined) return expiresIn;
	return Math.max(0, Math.min(expiresIn, expiresAt - Math.floor(Date.now() / 1000)));
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
	 * The token's `jti`; a fresh UUID unless supplied. Supplied when the
	 * identity must be reserved before signing: the refresh grant commits the
	 * rotation to the family store first, so a lost race costs no signature.
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
	// Both may be reservations made before signing. An empty `jti` would sign a
	// token with no identity for replay checks; an `issuedAt` that is not whole
	// epoch seconds would sign an `iat` / `exp` no verifier reads as intended.
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

	// Built in one expression so the readonly `confirmation` is assigned
	// without a cast.
	return {
		token,
		...(expiresIn !== undefined ? { expiresIn, expiresAt: now + expiresIn } : {}),
		...(audience !== null && audience !== undefined ? { audience } : {}),
		...(issuer !== null && issuer !== undefined ? { issuer } : {}),
		...(subject !== null && subject !== undefined ? { subject } : {}),
		...(scope !== null && scope !== undefined ? { scope } : {}),
		...(tokenType !== undefined ? { tokenType } : {}),
		...(confirmation !== undefined ? { confirmation } : {}),
	};
};
