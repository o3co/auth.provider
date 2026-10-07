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

import {
	createFakeIdp as createSharedFakeIdp,
	type FakeIdp,
} from "@o3co/auth-provider-core/testing";

export type { FakeIdp };

/**
 * The fake OpenID Provider these tests run the real library against (#524):
 * core's shared one (`@o3co/auth-provider-core/testing`), set up as an issuer
 * a generic OIDC client discovers — the discovery document served at
 * `<issuer>/.well-known/openid-configuration`, every endpoint a path under
 * the issuer, UserInfo published unless `userinfo: false`, an end-session
 * endpoint only with `endSession: true`, and no id_token on a refresh unless
 * a test turns `refreshWithIdToken` on.
 */
export interface FakeIdpOptions {
	readonly issuer: string;
	readonly clientId?: string;
	readonly sub?: string;
	/** Publish an `end_session_endpoint`. Default: no. */
	readonly endSession?: boolean;
	/** Publish a `userinfo_endpoint`. Default: yes. */
	readonly userinfo?: boolean;
}

export async function createFakeIdp(options: FakeIdpOptions): Promise<FakeIdp> {
	const issuer = options.issuer.replace(/\/$/, "");
	const idp = await createSharedFakeIdp({
		issuer,
		discovery: true,
		...(options.userinfo === false ? {} : { userinfoEndpoint: `${issuer}/userinfo` }),
		...(options.endSession ? { endSessionEndpoint: `${issuer}/logout` } : {}),
		...(options.clientId !== undefined ? { clientId: options.clientId } : {}),
		...(options.sub !== undefined ? { sub: options.sub } : {}),
	});
	idp.refreshWithIdToken = false;
	return idp;
}
