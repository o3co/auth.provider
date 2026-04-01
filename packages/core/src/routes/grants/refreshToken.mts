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
import jwt, { type JwtPayload } from "jsonwebtoken";

import { formatObject, generateToken, generateTokenResponse } from "./token.mjs";
import type { GrantContext, GrantDependencies, GrantHandler } from "./types.mjs";

export const createRefreshTokenGrant = (deps: GrantDependencies): GrantHandler => {
	const { config } = deps;

	return {
		async handle({ req, res, issuer }: GrantContext): Promise<void> {
			const { refresh_token: refreshTokenValue, client_id } = req.body;

			if (!refreshTokenValue) {
				res.status(400).json({ message: "refresh_token is required" });
				return;
			}

			let tokenPayload: JwtPayload;
			try {
				tokenPayload = jwt.verify(refreshTokenValue, config.oauth.jwt.secret) as JwtPayload;
			} catch {
				res.status(400).json({ message: "invalid refresh_token" });
				return;
			}

			if (tokenPayload.type !== "refresh") {
				res.status(400).json({ message: "invalid refresh_token" });
				return;
			}

			// Validate client_id matches audience if provided
			const tokenAud = Array.isArray(tokenPayload.aud) ? tokenPayload.aud[0] : tokenPayload.aud;
			if (client_id && tokenAud !== client_id) {
				res.status(400).json({ message: "invalid client_id" });
				return;
			}

			const { user, client, scopes: existingScopes } = tokenPayload;
			const refreshPayload = formatObject({ user, client, ip: req.ip });

			res.status(200).json(
				generateTokenResponse({
					accessToken: generateToken(refreshPayload, {
						expiresIn: config.oauth.accessToken.expiresIn,
						secret: config.oauth.jwt.secret,
						issuer,
						audience: tokenAud ?? client_id ?? null,
						scopes: existingScopes as string[] | null,
						type: "access",
					}),
					refreshToken: generateToken(refreshPayload, {
						expiresIn: config.oauth.refreshToken.expiresIn,
						secret: config.oauth.jwt.secret,
						issuer,
						audience: tokenAud ?? client_id ?? null,
						scopes: existingScopes as string[] | null,
						type: "refresh",
					}),
				}),
			);
		},
	};
};
