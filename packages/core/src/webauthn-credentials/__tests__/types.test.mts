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
import { describe, expectTypeOf, it } from "vitest";
import type {
	AuthenticatorTransport,
	WebAuthnCredential,
	WebAuthnCredentialStore,
} from "../types.mjs";

describe("WebAuthnCredentialStore types (spec §2.3.1)", () => {
	it("declares the contract operations", () => {
		expectTypeOf<WebAuthnCredentialStore["registerCredential"]>().toEqualTypeOf<
			(record: WebAuthnCredential) => Promise<void>
		>();
		expectTypeOf<WebAuthnCredentialStore["findByCredentialId"]>().toEqualTypeOf<
			(credentialId: string) => Promise<WebAuthnCredential | null>
		>();
		expectTypeOf<WebAuthnCredentialStore["listByUserId"]>().toEqualTypeOf<
			(userId: string) => Promise<readonly WebAuthnCredential[]>
		>();
		expectTypeOf<WebAuthnCredentialStore["updateSignCount"]>().toEqualTypeOf<
			(
				credentialId: string,
				args: {
					readonly expectedCurrentSignCount: number;
					readonly newSignCount: number;
					readonly lastUsedAt: Date;
				},
			) => Promise<boolean>
		>();
		expectTypeOf<WebAuthnCredentialStore["remove"]>().toEqualTypeOf<
			(credentialId: string) => Promise<void>
		>();
	});

	it("WebAuthnCredential record shape", () => {
		expectTypeOf<WebAuthnCredential>().toEqualTypeOf<{
			readonly userId: string;
			readonly credentialId: string;
			readonly publicKey: Uint8Array;
			readonly signCount: number;
			readonly transports?: ReadonlyArray<AuthenticatorTransport>;
			readonly backedUp: boolean;
			readonly createdAt: Date;
			readonly lastUsedAt?: Date;
			readonly nickname?: string;
		}>();
	});
});
