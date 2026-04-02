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
import { SignJWT } from "jose";
import type { KeyStore } from "#/keys/KeyStore.mjs";

export const formatObject = <T extends object>(data: T): Partial<T> => {
	return Object.fromEntries(Object.entries(data).filter(([, v]) => v)) as Partial<T>;
};

export interface Token {
	token: string;
	expiresIn?: number;
	scopes?: string[];
	type?: "access" | "refresh";
	audience?: string;
	issuer?: string;
}

export interface IntermediateToken {
	accessToken: Token;
	refreshToken?: Token;
}

export interface TokenResponse {
	access_token: string;
	token_type: string;
	scope?: string;
	refresh_token?: string | null;
	expires_in?: number;
}

export const generateTokenResponse = ({
	accessToken,
	refreshToken = undefined,
}: IntermediateToken): TokenResponse => {
	return {
		access_token: accessToken.token,
		token_type: "Bearer",
		...formatObject({
			scope: accessToken.scopes?.join(" "),
			refresh_token: refreshToken ? refreshToken.token : null,
			expires_in: accessToken.expiresIn,
		}),
	};
};

export interface GenerateTokenOptions {
	expiresIn?: number;
	keyStore: KeyStore;
	issuer?: string | null;
	audience?: string | null;
	scopes?: string[] | null;
	type?: "access" | "refresh" | null;
}

export const generateToken = async (
	data: object,
	{
		expiresIn = undefined,
		keyStore,
		issuer = null,
		audience = null,
		scopes = null,
		type = null,
	}: GenerateTokenOptions,
): Promise<Token> => {
	const { kid, privateKey } = keyStore.getSigningKey();

	let builder = new SignJWT({
		...data,
		...(scopes ? { scopes } : {}),
		...(type ? { type } : {}),
	}).setProtectedHeader({ alg: keyStore.algorithm, kid });

	if (expiresIn !== undefined) {
		builder = builder.setExpirationTime(`${expiresIn}s`);
	}
	if (issuer != null) {
		builder = builder.setIssuer(issuer);
	}
	if (audience != null) {
		builder = builder.setAudience(audience);
	}

	const token = await builder.sign(privateKey);

	const result: Token = { token };

	if (expiresIn !== undefined) result.expiresIn = expiresIn;
	if (audience !== null && audience !== undefined) result.audience = audience;
	if (issuer !== null && issuer !== undefined) result.issuer = issuer;
	if (scopes !== null && scopes !== undefined) result.scopes = scopes;
	if (type !== null && type !== undefined) result.type = type;

	return result;
};
