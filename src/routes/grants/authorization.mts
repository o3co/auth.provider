/*
 * Copyright 2026 1o1 Inc.
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
import crypto from "node:crypto";

import { formatObject, generateToken, generateTokenResponse } from "./token.mjs";
import type { GrantContext, GrantDependencies, GrantHandler } from "./types.mjs";

export const createAuthorizationGrant = (deps: GrantDependencies): GrantHandler => {
	const { config, codeRepository } = deps;

	return {
		async handle({ req, res, issuer }: GrantContext): Promise<void> {
			const { code, code_verifier = null, client_id } = req.body;

			if (!code || code !== req.session.code) {
				res.status(400).json({ message: "invalid code" });
				return;
			}

			if (!client_id || client_id !== req.session.code_client_id) {
				res.status(400).json({ message: "invalid client_id" });
				return;
			}

			// Load code data from repository
			const codeData = await codeRepository.getByCode(code);
			if (!codeData) {
				res.status(400).json({ message: "invalid code" });
				return;
			}

			// Consume code: remove from both repository and session (replay attack prevention)
			await codeRepository.removeByCode(code);
			const grantedScopes = req.session.granted_scopes;
			req.session.code = undefined;
			req.session.code_client_id = undefined;
			req.session.granted_scopes = undefined;

			// Validate code_verifier using code data from repository
			if (codeData.code_challenge_method) {
				if (!code_verifier) {
					res.status(400).json({ message: "code_verifier required" });
					return;
				}
				// RFC 7636: must be 43-128 characters, unreserved characters only
				if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(code_verifier)) {
					res.status(400).json({ message: "invalid code_verifier format" });
					return;
				}
				switch (codeData.code_challenge_method) {
					case "S256": {
						const hash = crypto.createHash("sha256").update(code_verifier).digest();
						const base64url = hash.toString("base64url");
						if (base64url !== codeData.code_challenge) {
							res.status(400).json({ message: "invalid code_verifier" });
							return;
						}
						break;
					}
					case "plain":
						if (code_verifier !== codeData.code_challenge) {
							res.status(400).json({ message: "invalid code_verifier" });
							return;
						}
						break;
					default:
						res.status(400).json({
							message: "invalid code_challenge_method",
						});
						return;
				}
			}

			const payload = formatObject({
				user: req.session.user,
				client: req.session.client,
				ip: req.ip,
			});

			res.status(200).json(
				generateTokenResponse({
					accessToken: generateToken(payload, {
						expiresIn: config.oauth.accessToken.expiresIn,
						secret: config.oauth.jwt.secret,
						issuer,
						audience: client_id,
						scopes: grantedScopes,
						type: "access",
					}),
					refreshToken: generateToken(payload, {
						expiresIn: config.oauth.refreshToken.expiresIn,
						secret: config.oauth.jwt.secret,
						issuer,
						audience: client_id,
						scopes: grantedScopes,
						type: "refresh",
					}),
				}),
			);
		},
	};
};
