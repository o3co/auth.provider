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
 * The denial audits count their own routes' refusals, and nothing beneath
 * them.
 *
 * `router.use("/:grantId/token", audit)` matched every path beneath the
 * token route as well, so a request to `/:grantId/token/extra` — answered
 * 404 by this router, or refused by the middleware every path here shares —
 * was audited as a token denial. The same for revoke and reauthorize.
 */

import request from "supertest";
import { describe, expect, it } from "vitest";
import { basic, CLIENT_ID, GRANT_ID, harness, SUBJECT } from "./harness.mjs";

const DENIALS: Readonly<Record<string, string>> = {
	token: "federation.grant.token.denied",
	revoke: "federation.grant.revoke.denied",
	reauthorize: "federation.grant.request.denied",
};

describe("the denial audits — their own routes only", () => {
	it.each(["token", "revoke", "reauthorize"])(
		"audits no denial for a path beneath /:grantId/%s",
		async (operation) => {
			const h = harness();
			await h.seed();

			const response = await request(h.app)
				.post(`/oauth/federation-grants/${GRANT_ID}/${operation}/extra`)
				.set("Authorization", basic())
				.send({ sub: SUBJECT });

			expect(response.status).toBe(404);
			expect(h.events.filter((event) => Object.values(DENIALS).includes(event.type))).toEqual([]);
		},
	);

	it.each([
		["token", ""],
		["token", "/"],
		["revoke", ""],
		["revoke", "/"],
		["reauthorize", ""],
		["reauthorize", "/"],
	])("still audits a refused credential at /:grantId/%s%s itself", async (operation, slash) => {
		const h = harness();
		await h.seed();

		const response = await request(h.app)
			.post(`/oauth/federation-grants/${GRANT_ID}/${operation}${slash}`)
			.set("Authorization", basic(CLIENT_ID, "wrong"))
			.send({ sub: SUBJECT });

		expect(response.status).toBe(401);
		expect(h.events.filter((event) => event.type === DENIALS[operation])).toHaveLength(1);
	});
});
