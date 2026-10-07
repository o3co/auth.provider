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
 * The fetch the resolver builds for itself: core's outbound fetch for a URL a
 * request names, under core's outbound policy and with the resolver's own
 * deadline and cap. Core's public factory is observed, its implementation
 * kept.
 */

import { createOutboundFetch } from "@o3co/auth-provider-core";
import { createTestOutboundPolicy } from "@o3co/auth-provider-core/testing";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	createClientIdMetadataDocumentResolver,
	DEFAULT_CIMD_MAX_BYTES,
	DEFAULT_CIMD_TIMEOUT_MS,
} from "#/clients/clientIdMetadataDocument.mjs";

vi.mock("@o3co/auth-provider-core", async (importOriginal) => {
	const core = await importOriginal<typeof import("@o3co/auth-provider-core")>();
	return { ...core, createOutboundFetch: vi.fn(core.createOutboundFetch) };
});

const built = vi.mocked(createOutboundFetch);

beforeEach(() => {
	built.mockClear();
});

describe("the resolver builds its document fetch from core's outbound fetch", () => {
	it("for a URL a request names, under the policy and with the default deadline and cap", () => {
		const outboundPolicy = createTestOutboundPolicy({ deniedHosts: ["denied.example"] });
		createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy,
		});

		expect(built.mock.calls).toEqual([
			[
				{
					policy: outboundPolicy,
					source: "request",
					timeoutMs: DEFAULT_CIMD_TIMEOUT_MS,
					maxResponseBytes: DEFAULT_CIMD_MAX_BYTES,
				},
			],
		]);
		expect(DEFAULT_CIMD_MAX_BYTES).toBe(5120);
	});

	it("with the deadline and cap the operator set", () => {
		const outboundPolicy = createTestOutboundPolicy();
		createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy,
			timeoutMs: 1234,
			maxBytes: 4096,
		});

		expect(built.mock.calls).toEqual([
			[{ policy: outboundPolicy, source: "request", timeoutMs: 1234, maxResponseBytes: 4096 }],
		]);
	});

	it("builds none when a substitute is given", () => {
		createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy: createTestOutboundPolicy(),
			fetch: (async () => new Response(null)) as typeof fetch,
		});

		expect(built).not.toHaveBeenCalled();
	});
});
