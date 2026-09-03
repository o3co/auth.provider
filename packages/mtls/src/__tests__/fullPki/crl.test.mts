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
 * The CRL resolver on its own: what it verifies before it stores, and how it
 * behaves when many callers miss the cache at once or a distribution point
 * is down. `validate.test.mts` covers the policy decisions built on top.
 */

import { describe, expect, it } from "vitest";
import { createCrlResolver } from "#/fullPki/crl.mjs";
import type { GuardedFetch } from "#/fullPki/fetchGuard.mjs";
import {
	basicConstraints,
	clientAuthEku,
	crlDistributionPoints,
	KEY_USAGE,
	keyUsage,
	mintCa,
	mintCrl,
	mintIntermediate,
	mintLeaf,
} from "./pkiFactory.mjs";

const NOW = new Date("2027-01-01T00:00:00Z");
const INT_CRL_URL = "http://crl.test/int.crl";
const ROOT_CRL_URL = "http://crl.test/root.crl";

/** root → intermediate → leaf, each non-anchor naming its issuer's distribution point. */
const chain = async () => {
	const root = await mintCa("Root", 1);
	const int = await mintIntermediate("Intermediate", 2, root, {
		extensions: [
			basicConstraints(true),
			keyUsage(KEY_USAGE.keyCertSign | KEY_USAGE.cRLSign),
			crlDistributionPoints([ROOT_CRL_URL]),
		],
	});
	const leaf = await mintLeaf("client", 10, int, {
		extensions: [
			basicConstraints(false),
			keyUsage(KEY_USAGE.digitalSignature),
			clientAuthEku(),
			crlDistributionPoints([INT_CRL_URL]),
		],
	});
	return { root, int, leaf };
};

/**
 * A `GuardedFetch` answering from a table. `"down"` answers as an HTTP error,
 * which is what the guard reports for an unreachable responder.
 */
const stubGuardedFetch = (table: Record<string, Uint8Array | "down">) => {
	const calls: string[] = [];
	const fetch: GuardedFetch = async (url) => {
		calls.push(url);
		const entry = table[url];
		if (entry === undefined || entry === "down") {
			return { ok: false, reason: "http_error", detail: "HTTP 503" };
		}
		return { ok: true, bytes: entry };
	};
	return { fetch, calls };
};

describe("CRL resolver — signature verification before caching", () => {
	it("reports a CRL the issuer did not sign as bad_signature, and never caches it", async () => {
		// Caching a forged CRL would let one injected response over plain http
		// pin a refusal for every client of that distribution point until the
		// entry expires. Verification therefore happens before storage, and a
		// failure leaves nothing behind: the next lookup goes back to the
		// distribution point.
		const { int, leaf } = await chain();
		const impostor = await mintCa("Impostor", 900);
		const forged = await mintCrl({ issuer: int, revoked: [], signingKeys: impostor.keys });
		const { fetch, calls } = stubGuardedFetch({ [INT_CRL_URL]: forged });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600 });

		const first = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(first).toMatchObject({ ok: false, reason: "bad_signature" });
		expect(resolver.size()).toBe(0);

		const second = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(second).toMatchObject({ ok: false, reason: "bad_signature" });
		expect(calls).toEqual([INT_CRL_URL, INT_CRL_URL]);
	});

	it("does not honour a genuine CRL for a certificate whose issuer is a different CA", async () => {
		// The CRL is checked against the issuer of the certificate being
		// looked up — not against whichever CA happens to have signed it.
		const { root, int, leaf } = await chain();
		const genuine = await mintCrl({ issuer: int, revoked: [] });
		const { fetch } = stubGuardedFetch({ [INT_CRL_URL]: genuine });
		const resolver = createCrlResolver({ fetch, cacheTtlSeconds: 3_600 });

		const wrongIssuer = await resolver.resolve(leaf.cert, root.cert, NOW);
		expect(wrongIssuer).toMatchObject({ ok: false, reason: "bad_signature" });
		expect(resolver.size()).toBe(0);

		const rightIssuer = await resolver.resolve(leaf.cert, int.cert, NOW);
		expect(rightIssuer.ok).toBe(true);
		expect(resolver.size()).toBe(1);
	});
});
