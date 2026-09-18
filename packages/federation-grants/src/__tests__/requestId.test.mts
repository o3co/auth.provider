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
 * `x-request-id` on every exit this package owns (#593, D18).
 *
 * It arrives in slice 4 rather than with the first audit event because both
 * routes and the background audit bridge need it at once: a refresh that
 * persists after the HTTP response is the reason the correlation has to be the
 * *request's*, not one the late worker mints for itself — an ID generated
 * there cannot be connected to the call that started the rotation.
 *
 * It is caller-controlled metadata and nothing else: never authentication,
 * never an idempotency key, never a lock key, never a trusted identifier of a
 * person. That is why the accepted shape is narrow and an unusable value is
 * replaced rather than repaired — trimming an invalid value into a valid one
 * would echo attacker-chosen bytes into an operator's logs.
 *
 * The disabled routes are the ones that exist in this commit, and the rule is
 * the same on every exit, so they are where it is pinned.
 */

import type { BootstrapMap } from "@o3co/auth-provider-core";
import { createApp } from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { federationGrantsModules } from "#/index.mjs";
import { resolveRequestId } from "#/requestId.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const boot = async () => {
	const handle = await createApp({
		modules: [...federationGrantsModules],
		bootstrapComponents: {
			config: makeValidCoreConfig(),
			pathResolver: (s: string) => s,
		} as unknown as BootstrapMap,
	});
	const app = express();
	app.use(handle.router);
	return { handle, app };
};

/**
 * The header as Node types it — `string | string[] | undefined` — rather than
 * as Express delivers it.
 *
 * Node joins duplicate occurrences of an ordinary header into one
 * comma-separated string, so the array never reaches this through an HTTP
 * request, and the end-to-end test below can only observe the joined form. The
 * rule is the same for both and is stated once, here, where the array can
 * actually be passed: no element of it is a value that one caller chose.
 */
describe("resolveRequestId", () => {
	it("takes a value that matches the accepted shape", () => {
		expect(resolveRequestId("job-42:attempt/3=ok")).toBe("job-42:attempt/3=ok");
	});

	it("refuses an array outright rather than resolving it to its first element", () => {
		expect(resolveRequestId(["first", "second"])).toMatch(UUID);
	});

	it("refuses an array even when it carries one element", () => {
		// One occurrence that a stack chose to keep as an array is still not a
		// string, and reading it as one is the step that makes the two-element
		// case look resolvable.
		expect(resolveRequestId(["only"])).toMatch(UUID);
	});

	it("refuses the joined form a duplicated header actually arrives as", () => {
		expect(resolveRequestId("first, second")).toMatch(UUID);
		expect(resolveRequestId("first,second")).toMatch(UUID);
	});

	it("generates one for an absent header", () => {
		expect(resolveRequestId(undefined)).toMatch(UUID);
	});
});

describe("x-request-id", () => {
	it("echoes a supplied value that matches the accepted shape", async () => {
		const { handle, app } = await boot();
		const response = await request(app)
			.post("/oauth/federation-grants/g1/token")
			.set("x-request-id", "job-42:attempt/3=ok");

		expect(response.headers["x-request-id"]).toBe("job-42:attempt/3=ok");
		await handle.dispose();
	});

	it("generates one when none was supplied", async () => {
		const { handle, app } = await boot();
		const response = await request(app).post("/oauth/federation-grants/g1/token");

		expect(response.headers["x-request-id"]).toMatch(UUID);
		await handle.dispose();
	});

	it("replaces an unusable value rather than trimming it into a usable one", async () => {
		const { handle, app } = await boot();
		// A space is outside the accepted set, and the prefix before it is not
		// what the caller asked to be correlated by.
		const response = await request(app)
			.post("/oauth/federation-grants/g1/token")
			.set("x-request-id", "job 42");

		expect(response.headers["x-request-id"]).not.toBe("job 42");
		expect(response.headers["x-request-id"]).not.toBe("job");
		expect(response.headers["x-request-id"]).toMatch(UUID);
		await handle.dispose();
	});

	it("replaces a value that is longer than the accepted shape", async () => {
		const { handle, app } = await boot();
		const response = await request(app)
			.post("/oauth/federation-grants/g1/token")
			.set("x-request-id", "a".repeat(129));

		expect(response.headers["x-request-id"]).toMatch(UUID);
		await handle.dispose();
	});

	it("does not take a supplied ID from a header sent more than once", async () => {
		// Whatever the stack does with the second occurrence — join them, keep
		// an array, keep the first — none of them is a value one caller chose.
		const { handle, app } = await boot();
		const response = await request(app)
			.post("/oauth/federation-grants/g1/token")
			.set("x-request-id", ["first", "second"]);

		expect(response.headers["x-request-id"]).not.toBe("first");
		expect(response.headers["x-request-id"]).not.toBe("second");
		expect(response.headers["x-request-id"]).toMatch(UUID);
		await handle.dispose();
	});

	it("gives two requests two different generated IDs", async () => {
		const { handle, app } = await boot();
		const first = await request(app).post("/oauth/federation-grants/g1/token");
		const second = await request(app).post("/oauth/federation-grants/g1/token");

		expect(first.headers["x-request-id"]).not.toBe(second.headers["x-request-id"]);
		await handle.dispose();
	});
});
