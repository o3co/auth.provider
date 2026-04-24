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
	GrantRegistry,
	createSymmetricKeyStore,
	type ModuleContext,
} from "@o3co/auth-provider-core";
import type { Router } from "express";
import { describe, expect, it } from "vitest";
import { oauthDidModule } from "../module.mjs";
import type { DidDocument, DidDocumentResolver } from "../resolver/types.mjs";

const DID_URN = "urn:o3co:oauth:grant-type:did";

const mockResolver: DidDocumentResolver = {
	async resolve(_did: string): Promise<DidDocument> {
		throw new Error("not expected to be called in this test");
	},
};

const buildContext = (
	didConfig: Record<string, unknown> | undefined,
): ModuleContext => ({
	pathResolver: (s: string) => s,
	config: {
		oauth: {
			jwt: { secret: "test-secret" },
			accessToken: { expiresIn: 3600 },
			refreshToken: { expiresIn: 86400 },
			grants: { did: didConfig },
		},
	} as unknown as ModuleContext["config"],
	keyStore: createSymmetricKeyStore("test-secret"),
	grantRegistry: new GrantRegistry(),
	router: {} as Router,
});

describe("oauthDidModule", () => {
	it("registers DID grant under urn:o3co:oauth:grant-type:did when enabled", async () => {
		const ctx = buildContext({ enabled: true, supportedAlgorithms: ["ed25519_raw"] });
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		expect(ctx.grantRegistry.get(DID_URN)).toBeDefined();
	});

	it("does NOT register the bare 'did' string (URN-only policy)", async () => {
		const ctx = buildContext({ enabled: true, supportedAlgorithms: ["ed25519_raw"] });
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		expect(ctx.grantRegistry.get("did")).toBeUndefined();
	});

	it("is a no-op when did.enabled is false", async () => {
		const ctx = buildContext({ enabled: false });
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		expect(ctx.grantRegistry.get(DID_URN)).toBeUndefined();
		expect(ctx.grantRegistry.get("did")).toBeUndefined();
	});

	it("registers when did config is missing (enabled defaults to true)", async () => {
		const ctx = buildContext(undefined);
		await oauthDidModule({ resolver: mockResolver }).init(ctx);

		// Current behavior: undefined config → enabled !== false, so registered
		expect(ctx.grantRegistry.get(DID_URN)).toBeDefined();
	});
});
