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
 * These routes live UNDER another package's mount path (#593, D9).
 *
 * `oauthModule`'s router at `/oauth` parses the bodies of its own routes
 * only, so in the shipped composition nothing reads these routes' bodies
 * first. But `body-parser` does not parse a body twice: any router mounted
 * ahead of this one that parses every request under `/oauth` — as
 * `oauthModule`'s did until the device-grant fix scoped it — would skip this
 * package's own 16 KiB limit and hand the handler a body up to its own.
 *
 * Found by review. The bound is restated as a check of its own, ahead of the
 * parsers, so that it holds whatever else is mounted and in whatever order;
 * `withOauthMountedFirst` below stands in for such a router.
 */

import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { basic, harness, SUBJECT } from "./harness.mjs";

/** A router at `/oauth` that parses every body beneath it — what `oauthModule`'s did before it was scoped. */
const withOauthMountedFirst = (grants: express.Express): express.Express => {
	const app = express();
	const oauth = express.Router();
	oauth.use(express.json()).use(express.urlencoded({ extended: false }));
	oauth.post("/token", (_req, res) => {
		res.json({ ok: true });
	});
	app.use("/oauth", oauth);
	app.use(grants as unknown as express.RequestHandler);
	return app;
};

describe("mounted under another router's path", () => {
	it("keeps its own body limit when something else parsed the body first", async () => {
		const h = harness();
		await h.seed();
		const app = withOauthMountedFirst(h.app);

		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT, connection: "x".repeat(20_000) });

		expect(response.status).toBe(413);
		expect(response.body).toEqual({
			error: "invalid_request",
			error_description: "body_too_large",
		});
	});

	it("keeps its own body limit when nothing else is mounted", async () => {
		const h = harness();
		await h.seed();
		const response = await request(h.app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT, connection: "x".repeat(20_000) });

		expect(response.status).toBe(413);
	});

	it("accepts a body of exactly the limit, as the parser it stands in for does", async () => {
		// `express.json({ limit: "16kb" })` accepts exactly 16384 bytes. A
		// restatement of a bound that disagreed with the bound would be worse
		// than none: the same request would be accepted or refused depending on
		// what else happened to be mounted.
		const h = harness();
		await h.seed();
		const body = { sub: SUBJECT, connection: "" };
		const padding = 16_384 - Buffer.byteLength(JSON.stringify(body));
		body.connection = "x".repeat(padding);
		expect(Buffer.byteLength(JSON.stringify(body))).toBe(16_384);

		const response = await request(h.app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send(body);

		// Refused by core for naming a connection that is not the grant's — it
		// got past the limit, which is what is being checked.
		expect(response.status).toBe(400);
		expect(response.body.error_description).toBe("connection_mismatch");
	});

	it("still answers a body within the limit", async () => {
		const h = harness();
		await h.seed();
		const app = withOauthMountedFirst(h.app);

		const response = await request(app)
			.post("/oauth/federation-grants/g-1/token")
			.set("Authorization", basic())
			.send({ sub: SUBJECT });

		expect(response.status).toBe(200);
	});
});
