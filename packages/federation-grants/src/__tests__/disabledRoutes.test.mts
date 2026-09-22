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
 * What a deployment that has not enabled offline delegation answers (#593).
 *
 * `enabled = false` is the default, and the promise it makes is that the
 * package is indistinguishable from not being installed: the same 404, the
 * same body, and no dependency on anything the feature would need. A 404 that
 * carried a description naming the feature would tell an unauthenticated
 * caller that this deployment could do offline delegation if someone flipped a
 * key; a 404 that first parsed a body, authenticated a client or read a store
 * would give it a way to measure that.
 */

import type { BootstrapMap, ClientRepository } from "@o3co/auth-provider-core";
import { createApp, createSymmetricKeyStore } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { federationGrantsModules } from "#/index.mjs";

/** Every call is a failure: nothing on the disabled path may reach a client record. */
const refusingClientRepository: ClientRepository = {
	findById: async () => {
		throw new Error("the disabled route read a client record");
	},
	authenticate: async () => {
		throw new Error("the disabled route authenticated a client");
	},
};

const makeBoot = (federationGrants?: Record<string, unknown>): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			...(federationGrants === undefined ? {} : { federationGrants }),
		},
		pathResolver: (s: string) => s,
		// Present so that this file keeps saying what it is about once the
		// token route authenticates: what it asserts is that the disabled path
		// never reaches them, not that a deployment may omit them.
		clientRepository: refusingClientRepository,
		keyStore: createSymmetricKeyStore("test-secret-at-least-32-chars!!!"),
	}) as unknown as BootstrapMap;

const boot = async (federationGrants?: Record<string, unknown>) => {
	const handle = await createApp({
		modules: [...federationGrantsModules],
		bootstrapComponents: makeBoot(federationGrants),
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

describe("the routes a disabled deployment mounts", () => {
	it("boots with no grant store, no rate limiter and no audit sink", async () => {
		// The feature's dependencies are the feature's. A composition that
		// installs the package and leaves it off must not be asked for the
		// store it would need if it turned it on.
		const { handle } = await boot();
		expect(handle.components.federationGrantStore).toBeUndefined();
		await handle.dispose();
	});

	it("answers 404 not_found on the token route, with no description", async () => {
		const { handle, app } = await boot();
		const response = await request(app)
			.post("/oauth/federation-grants/g1/token")
			.send({ sub: "local-subject" });

		expect(response.status).toBe(404);
		// Byte-identical to what a deployment without the package answers.
		expect(response.body).toEqual({ error: "not_found" });
		await handle.dispose();
	});

	it("answers the lodging routes and the browser half the same way (slice 6)", async () => {
		const { handle, app } = await boot();
		const lodged = await request(app)
			.post("/oauth/federation-grants")
			.send({ sub: "local-subject", connection: "calendar" });
		expect(lodged.status).toBe(404);
		expect(lodged.body).toEqual({ error: "not_found" });
		// The browser half is a navigation: a plain 404, no JSON, no redirect to
		// a login page for a feature that is not there.
		for (const path of [
			"/session/federation-grants/connect?request=h",
			"/session/federation-grants/consent?challenge=c",
		]) {
			const response = await request(app).get(path);
			expect(response.status, path).toBe(404);
			expect(response.headers["content-type"], path).toMatch(/^text\/plain/);
			expect(response.headers.location, path).toBeUndefined();
		}
		await handle.dispose();
	});

	it("answers the same 404 on the status route", async () => {
		const { handle, app } = await boot();
		const response = await request(app)
			.post("/oauth/federation-grants/g1/status")
			.send({ sub: "local-subject" });

		expect(response.status).toBe(404);
		expect(response.body).toEqual({ error: "not_found" });
		await handle.dispose();
	});

	it("answers 404 for a method the routes do not have, including a GET status alias", async () => {
		const { handle, app } = await boot();
		for (const response of [
			await request(app).get("/oauth/federation-grants/g1/status"),
			await request(app).put("/oauth/federation-grants/g1/token"),
			await request(app).get("/oauth/federation-grants/g1"),
		]) {
			expect(response.status).toBe(404);
			expect(response.body).toEqual({ error: "not_found" });
		}
		await handle.dispose();
	});

	it("sets the cache directives the live routes will, so nothing caches the refusal", async () => {
		// A bare 404 with no directives is the shape an intermediary caches
		// heuristically, and a cached "this deployment has no federation
		// grants" would outlive the operator turning them on.
		const { handle, app } = await boot();
		const response = await request(app).post("/oauth/federation-grants/g1/token");

		expect(response.headers["cache-control"]).toBe("no-store");
		expect(response.headers.pragma).toBe("no-cache");
		await handle.dispose();
	});

	it("refuses an explicit enabled = false the same way as an absent section", async () => {
		const { handle, app } = await boot({ enabled: false });
		const response = await request(app).post("/oauth/federation-grants/g1/token");

		expect(response.status).toBe(404);
		expect(response.body).toEqual({ error: "not_found" });
		await handle.dispose();
	});
});
