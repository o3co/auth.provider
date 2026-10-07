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
 * The `csrfTokenSigner` slot: the CSRF token's signing key has one
 * owner — the session store's module, which owns `session.secret` — and it
 * reaches the session module's `csrfGuard` provider as this narrow signer, the
 * key derived and kept inside it: the slot's shape, its wiring between
 * modules, the signature's bounds and the test double. The slot's contract
 * suite is the test kit's, and runs over this double there.
 */

import { describe, expect, expectTypeOf, it } from "vitest";
import type { CsrfTokenSigner } from "#/browser-session/types.mjs";
import {
	CSRF_SIGNATURE_MAX_LENGTH,
	CSRF_SIGNATURE_MIN_LENGTH,
	createApp,
	defineModule,
	type ProviderDeps,
} from "#/index.mjs";
import type { ComponentMap } from "#/modules/manifest/component-map.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestCsrfTokenSigner } from "#/testing/index.mjs";

describe("the csrfTokenSigner slot", () => {
	it("is optional, and holds sign and verify", () => {
		expectTypeOf<ComponentMap["csrfTokenSigner"]>().toEqualTypeOf<CsrfTokenSigner | undefined>();
		expectTypeOf<
			ProviderDeps<"csrfTokenSigner">["csrfTokenSigner"]
		>().toEqualTypeOf<CsrfTokenSigner>();
		expectTypeOf<CsrfTokenSigner["sign"]>().toEqualTypeOf<(payload: string) => string>();
		expectTypeOf<CsrfTokenSigner["verify"]>().toEqualTypeOf<
			(payload: string, signature: string) => boolean
		>();
		expect(true).toBe(true);
	});

	it("is filled by a module, and read by another", async () => {
		const signer = createTestCsrfTokenSigner();
		let seen: CsrfTokenSigner | undefined;
		const owner = defineModule({
			name: "test-csrf-token-signer-owner",
			provides: { csrfTokenSigner: () => signer },
		});
		const reader = defineModule({
			name: "test-csrf-token-signer-reader",
			requires: ["csrfTokenSigner"] as const,
			contributes: {
				grantMiddleware: [
					(deps) => {
						seen = deps.csrfTokenSigner;
						return null;
					},
				],
			},
		});
		const handle = await createApp({
			modules: [owner, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
			} as never,
		});
		try {
			expect(seen).toBe(signer);
		} finally {
			await handle.dispose();
		}
	});
});

describe("the signature's bounds", () => {
	it("are 22 characters, at least 128 bits of base64url, and 512, exported from core", () => {
		expect(CSRF_SIGNATURE_MIN_LENGTH).toBe(22);
		expect(CSRF_SIGNATURE_MAX_LENGTH).toBe(512);
	});
});

describe("createTestCsrfTokenSigner", () => {
	it("draws a key of its own: two doubles sign one payload differently", () => {
		expect(createTestCsrfTokenSigner().sign("payload")).not.toBe(
			createTestCsrfTokenSigner().sign("payload"),
		);
	});
});
