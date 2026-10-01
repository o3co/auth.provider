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
 * The OAuth package's testing entry (`@o3co/auth-provider-oauth/testing`):
 * what a test builds the `oauth` section with, so no test writes it by hand.
 */

import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";

/** What {@link oauthConfigForTests} lays over the section's defaults. */
export interface OAuthConfigForTestsOptions {
	/** `oauth.jwt.issuer`; core's test issuer unless given. */
	readonly issuer?: string;
	/** `oauth.accessToken.expiresIn`, in seconds; 3600 unless given. */
	readonly accessTokenExpiresIn?: number;
	/** `oauth.refreshToken.expiresIn`, in seconds; 86400 unless given. */
	readonly refreshTokenExpiresIn?: number;
}

/**
 * The `oauth` section, as a configuration fragment to lay over a
 * configuration: the keys core's schema still declares (`jwt`, `accessToken`,
 * `refreshToken` and the rest) from core's testing builder, and this
 * package's own keys (`consentPage`, `clientIdMetadataDocuments`) at
 * `config/reference.conf`'s defaults, with `options` laid over them. A fresh
 * object each call.
 */
export function oauthConfigForTests(options: OAuthConfigForTestsOptions = {}) {
	const { oauth } = makeValidCoreConfig();
	return {
		oauth: {
			...oauth,
			jwt: {
				...oauth.jwt,
				...(options.issuer === undefined ? {} : { issuer: options.issuer }),
			},
			accessToken: {
				...oauth.accessToken,
				...(options.accessTokenExpiresIn === undefined
					? {}
					: { expiresIn: options.accessTokenExpiresIn }),
			},
			refreshToken: {
				...oauth.refreshToken,
				...(options.refreshTokenExpiresIn === undefined
					? {}
					: { expiresIn: options.refreshTokenExpiresIn }),
			},
			consentPage: { url: "/consent" },
			clientIdMetadataDocuments: { enabled: false },
		},
	};
}
