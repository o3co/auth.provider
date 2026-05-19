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
 * boot/__tests__/token-binding-mechanisms.integration.test.mts
 *
 * Integration tests for the `tokenBindingMechanisms` contribution kind.
 *
 * Verifies:
 *   1. Empty collector → no synthesized middleware mounted.
 *   2. One mechanism contributed → single `tokenBindingMw` synthesized,
 *      `req.tokenBinding` populated with the mechanism's output.
 *   3. Two mechanisms contributed → ONE `tokenBindingMw` composed across
 *      both; under `intent-explicit` the explicit-intent mechanism wins
 *      over the ambient one when both succeed on the same request.
 *   4. Two mechanisms + `strict-mutual-exclusion` + both succeed → 400.
 *   5. Factory returns null → filtered; not included in the composition.
 *   6. dispatch-policy absent from config → defaults to `intent-explicit`.
 *
 * Per cross-mechanism dispatch refactor spec §6.1 at
 * `.claude/superpowers/specs/2026-05-19-wave-2-cross-mechanism-dispatch-refactor-spec.md`.
 */

import express, { type Request, type RequestHandler, Router } from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import type { TokenBinding } from "../../grants/tokenBinding.mjs";
import { createApp } from "../../index.mjs";
import type { TokenBindingMechanism } from "../../middleware/tokenBinding.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../types.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const makeBoot = (dispatchPolicy?: "intent-explicit" | "strict-mutual-exclusion"): BootstrapMap =>
	({
		config: {
			...makeValidCoreConfig(),
			oauth: {
				...makeValidCoreConfig().oauth,
				...(dispatchPolicy !== undefined
					? { tokenBinding: { "dispatch-policy": dispatchPolicy } }
					: {}),
			},
		} as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** Mechanism that always succeeds with the given kind (caller sets intentExplicit). */
const fixedMechanism = (
	kind: string,
	intentExplicit: boolean,
	confirmation: TokenBinding["confirmation"],
): TokenBindingMechanism => ({
	kind,
	intentExplicit,
	extract: async (_req: Request) => ({ kind, confirmation }),
});

const dpopMech = fixedMechanism("dpop", true, { jkt: "fake-jkt" });
const mtlsMech = fixedMechanism("mtls", false, { "x5t#S256": "fake-thumb" });

/** Mechanism that returns null (no signal in request). */
const absentMech = (kind: string): TokenBindingMechanism => ({
	kind,
	intentExplicit: false,
	extract: async () => null,
});

/** Observer route that records `req.tokenBinding` shape on a POST. */
const makeObserverModule = (received: { binding?: unknown }) =>
	defineModule({
		name: "observer",
		requires: [],
		optional: [],
		contributes: {
			routes: [
				() => {
					const router = Router();
					router.use(express.json());
					router.post("/token", ((req, res) => {
						// biome-ignore lint/suspicious/noExplicitAny: test-only req augmentation access
						received.binding = (req as any).tokenBinding;
						res.status(200).json({ ok: true });
					}) as RequestHandler);
					return { id: "test-token", mountPath: "/oauth", handler: router };
				},
			],
		},
	});

const contributingModule = (name: string, factory: () => TokenBindingMechanism | null) =>
	defineModule({
		name,
		requires: [],
		optional: [],
		contributes: {
			tokenBindingMechanisms: [() => factory()],
		},
	});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("tokenBindingMechanisms — core synthesis", () => {
	it("empty collector → no token-binding middleware mounted; req.tokenBinding undefined", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [makeObserverModule(received)],
			bootstrapComponents: makeBoot(),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});

	it("one mechanism → single composed middleware populates req.tokenBinding", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [contributingModule("only-dpop", () => dpopMech), makeObserverModule(received)],
			bootstrapComponents: makeBoot(),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		expect(received.binding).toEqual({
			kind: "dpop",
			confirmation: { jkt: "fake-jkt" },
		});

		await handle.dispose();
	});

	it("two mechanisms + intent-explicit + both succeed → explicit (dpop) wins, ambient (mtls) loses", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [
				// Register mtls (ambient) FIRST so we can prove dispatch-policy
				// — not registration order — picks the winner.
				contributingModule("ambient-mtls", () => mtlsMech),
				contributingModule("explicit-dpop", () => dpopMech),
				makeObserverModule(received),
			],
			bootstrapComponents: makeBoot("intent-explicit"),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		expect(received.binding).toEqual({
			kind: "dpop",
			confirmation: { jkt: "fake-jkt" },
		});

		await handle.dispose();
	});

	it("two mechanisms + strict-mutual-exclusion + both succeed → 400 invalid_request", async () => {
		const handle = await createApp({
			modules: [
				contributingModule("dpop", () => dpopMech),
				contributingModule("mtls", () => mtlsMech),
				makeObserverModule({}),
			],
			bootstrapComponents: makeBoot("strict-mutual-exclusion"),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");

		await handle.dispose();
	});

	it("factory returning null is filtered — surrounding mechanisms still mount", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [
				contributingModule("disabled", () => null),
				contributingModule("only-dpop", () => dpopMech),
				makeObserverModule(received),
			],
			bootstrapComponents: makeBoot(),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		// Disabled module did NOT crash; dpop binding still extracted.
		expect(received.binding).toEqual({
			kind: "dpop",
			confirmation: { jkt: "fake-jkt" },
		});

		await handle.dispose();
	});

	it("mechanism whose extract returns null does not produce a binding (still routed through synthesized mw)", async () => {
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [
				contributingModule("absent-dpop", () => absentMech("dpop")),
				makeObserverModule(received),
			],
			bootstrapComponents: makeBoot(),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		expect(received.binding).toBeUndefined();

		await handle.dispose();
	});

	it("dispatch-policy absent from config → defaults to intent-explicit", async () => {
		// No explicit oauth.tokenBinding in bootstrap config. The synthesis
		// step must fall through to "intent-explicit" so the explicit DPoP
		// mechanism still wins over the ambient mTLS one.
		const received: { binding?: unknown } = {};
		const handle = await createApp({
			modules: [
				contributingModule("ambient-mtls", () => mtlsMech),
				contributingModule("explicit-dpop", () => dpopMech),
				makeObserverModule(received),
			],
			bootstrapComponents: makeBoot(),
		});
		const app = express();
		app.use(express.json());
		app.use(handle.router);

		const res = await request(app).post("/oauth/token").send({});
		expect(res.status).toBe(200);
		expect(received.binding).toEqual({
			kind: "dpop",
			confirmation: { jkt: "fake-jkt" },
		});

		await handle.dispose();
	});
});
