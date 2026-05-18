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
	 * Echo of `GenerateTokenOptions.confirmation` when set. Read-only
	 * informational field for callers (e.g. audit log); does NOT drive
	 * claim emission — that is `GenerateTokenOptions.confirmation`'s job.
	 * See Wave 2 Token-binding Cluster spec §4.4.
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

export interface GenerateTokenResponseOptions {
	/**
	 * Wire-level token_type for the response envelope. Defaults to "Bearer".
	 * Set to "DPoP" when the issued access token has a DPoP confirmation
	 * (RFC 9449 §5). mTLS-bound tokens keep "Bearer" per RFC 8705 §3.
	 */
	readonly tokenType?: "Bearer" | "DPoP";
}

export const generateTokenResponse = (
	{ accessToken, refreshToken = undefined, idToken = undefined }: IntermediateToken,
	options?: GenerateTokenResponseOptions,
): TokenResponse => {
	return {
		access_token: accessToken.token,
		token_type: options?.tokenType ?? "Bearer",
		...formatObject({
			scope: accessToken.scope,
			refresh_token: refreshToken ? refreshToken.token : null,
			expires_in: accessToken.expiresIn,
			id_token: idToken ? idToken.token : undefined,
		}),
	};
};

export interface GenerateTokenOptions {
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
	}: GenerateTokenOptions,
): Promise<Token> => {
	const now = Math.floor(Date.now() / 1000);
	const claims: JWTPayload = {
		...(data as Record<string, unknown>),
		...(authorizedParty ? { azp: authorizedParty } : {}),
		...(scope ? { scope } : {}),
		iat: now,
		jti: randomUUID(),
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

	const result: Token = { token };

	if (expiresIn !== undefined) result.expiresIn = expiresIn;
	if (audience !== null && audience !== undefined) result.audience = audience;
	if (issuer !== null && issuer !== undefined) result.issuer = issuer;
	if (subject !== null && subject !== undefined) result.subject = subject;
	if (scope !== null && scope !== undefined) result.scope = scope;
	if (tokenType !== undefined) result.tokenType = tokenType;
	if (confirmation !== undefined)
		(result as { confirmation?: Confirmation }).confirmation = confirmation;

	return result;
};
