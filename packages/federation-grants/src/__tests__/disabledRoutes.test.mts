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
 * A deployment that has not enabled offline delegation: the routes module is
 * switched off by its section and registers nothing — no route, admission
 * action or rate-limit prefix — and asks for none of what the feature would
 * need. A request to either path is answered by whatever the host mounts
 * after the router, as when the package is not installed.
 */

import type { BootstrapMap } from "@o3co/auth-provider-core";
import { createApp } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { federationGrantsModules } from "#/index.mjs";

const makeBoot = (federationGrants?: Record<string, unknown>): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			...(federationGrants === undefined ? {} : { "federation-grants": federationGrants }),
		},
		pathResolver: (s: string) => s,
	}) as unknown as BootstrapMap;

/** Booted, with a host fallback after the router that names itself. */
const boot = async (federationGrants?: Record<string, unknown>) => {
	const handle = await createApp({
		modules: [...federationGrantsModules],
		bootstrapComponents: makeBoot(federationGrants),
	});
	const app = express();
	app.use(handle.router);
	app.use((_req, res) => {
		res.status(404).json({ answeredBy: "host" });
	});
	return { handle, app };
};

describe("a deployment with federation grants off", () => {
	it("boots with nothing the feature would need: no grant store, client repository, key store, rate limiter or audit sink", async () => {
		const { handle } = await boot();
		expect(handle.components.federationGrantStore).toBeUndefined();
		await handle.dispose();
	});

	it("mounts no route and registers no admission action", async () => {
		const { handle } = await boot();
		expect(handle.routes.filter((route) => route.contributedBy === "federation-grants")).toEqual(
			[],
		);
		expect(
			handle.components.sessionRequirementResolver?.action("federation_grants.connect"),
		).toBeUndefined();
		await handle.dispose();
	});

	it("leaves every request under either path to the host", async () => {
		const { handle, app } = await boot();
		for (const response of [
			await request(app).post("/oauth/federation-grants/g1/token").send({ sub: "s" }),
			await request(app).post("/oauth/federation-grants").send({ sub: "s" }),
			await request(app).get("/session/federation-grants/connect?request=h"),
		]) {
			expect(response.status).toBe(404);
			expect(response.body).toEqual({ answeredBy: "host" });
		}
		await handle.dispose();
	});

	it("reads an explicit enabled = false as an absent section does", async () => {
		const { handle, app } = await boot({ enabled: false });
		const response = await request(app).post("/oauth/federation-grants/g1/token");
		expect(response.body).toEqual({ answeredBy: "host" });
		await handle.dispose();
	});
});
