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
 * Fresh document URLs whose host names never resolve: each request answers
 * at its deadline, and the resolutions it gave up on stay counted by the
 * outbound fetch, so however many ids a caller invents, the resolutions
 * outstanding stop at the fetch's ceiling.
 */

import {
	createOutboundFetchForTesting,
	createTestOutboundPolicy,
	type OutboundTransport,
} from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import {
	createClientIdMetadataDocumentResolver,
	DEFAULT_CIMD_MAX_CONCURRENT_FETCHES,
} from "#/clients/clientIdMetadataDocument.mjs";

/** The outbound fetch's fixed ceiling on outstanding resolutions (core's `MAX_PENDING_LOOKUPS`). */
const CEILING = 16;

const unreachable: OutboundTransport = () => new Promise(() => undefined);

describe("fresh document URLs whose host names never resolve", () => {
	it("answer at their deadline and never push outstanding resolutions past the ceiling", async () => {
		let started = 0;
		const outboundPolicy = createTestOutboundPolicy();
		const resolver = createClientIdMetadataDocumentResolver({
			allowedScopes: [],
			allowedAudiences: [],
			outboundPolicy,
			fetch: createOutboundFetchForTesting({
				policy: outboundPolicy,
				source: "request",
				timeoutMs: 30,
				lookup: () => {
					started += 1;
					return new Promise(() => undefined);
				},
				transport: unreachable,
			}),
		});

		const rounds = Math.ceil((CEILING * 3) / DEFAULT_CIMD_MAX_CONCURRENT_FETCHES);
		let id = 0;
		for (let round = 0; round < rounds; round += 1) {
			const begun = Date.now();
			const answers = await Promise.all(
				Array.from({ length: DEFAULT_CIMD_MAX_CONCURRENT_FETCHES }, () => {
					id += 1;
					return resolver.resolve(`https://c${id}.example/client.json`);
				}),
			);
			expect(answers.every((answer) => answer === null)).toBe(true);
			expect(Date.now() - begun).toBeLessThan(2_000);
			expect(started).toBeLessThanOrEqual(CEILING);
		}
		expect(id).toBeGreaterThan(CEILING * 2);
		expect(started).toBe(CEILING);
	});
});
