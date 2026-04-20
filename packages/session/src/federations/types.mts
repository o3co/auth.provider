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

import type { User } from "@o3co/auth-provider-core";
import type { PassportStatic } from "passport";

export type FederationResult<T> =
	| { ok: true; value: T }
	| { ok: false; status: number; error: string; errorDescription: string };

export interface VerifyUserContext {
	verifyUser: (externalId: string) => Promise<User | null>;
}

export interface FederationProvider {
	readonly name: string;
	readonly scope: readonly string[];
	validateRedirect(url: string): FederationResult<void>;
	resolveCallbackRedirect(session: { redirectTo?: string }): FederationResult<string>;
	setupPassportStrategy(passport: PassportStatic, ctx: VerifyUserContext): Promise<void>;
}
