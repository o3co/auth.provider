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
import { formatObject, generateToken, generateTokenResponse } from "./token.mjs";
import type { GrantContext, GrantDependencies, GrantHandler } from "./types.mjs";

export const createSessionGrant = (deps: GrantDependencies): GrantHandler => {
	const { config } = deps;

	return {
		async handle({ req, res, issuer }: GrantContext): Promise<void> {
			if (!req.session.isAuthenticated) {
				res.status(401).json({ message: "unauthorized" });
				return;
			}

			const payload = formatObject({
				user: req.session.user,
				client: req.session.client,
				ip: req.ip,
			});

			res.status(200).json(
				generateTokenResponse({
					accessToken: generateToken(payload, {
						secret: config.oauth.jwt.secret,
						expiresIn: config.oauth.accessToken.expiresIn,
						issuer,
						type: "access",
					}),
				}),
			);
		},
	};
};
