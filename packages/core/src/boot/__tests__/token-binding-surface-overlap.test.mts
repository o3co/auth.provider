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
 * Boot-time detection of the v0.7 → v0.8 token-binding migration hazard
 * (#199 I4 / R3).
 *
 * A consumer who migrates to `tokenBindingMechanisms` but leaves their v0.7
 * `grantMiddleware`-mounted `tokenBindingMw` in place ends up with BOTH
 * surfaces active. `assembleApp` mounts the composed middleware first and
 * `grantMiddleware` contributions after, and `tokenBindingMw` assigns
 * `req.tokenBinding` unguarded — so the leftover legacy middleware wins on
 * every request and the `dispatch-policy` configured for the new surface is
 * silently inert.
 *
 * The failure mode looks exactly like success: no error, no behavioral
 * signal, and the new surface still appears wired. These tests pin the boot
 * warning that makes it visible, and pin that it does NOT fire for the two
 * legitimate shapes — a non-token-binding `grantMiddleware` alongside
 * mechanisms, and an un-migrated v0.7 deployment with no mechanisms at all.
 */

import express, { type Request, type RequestHandler, Router } from "express";
import { describe, expect, it } from "vitest";
import { createApp } from "../../index.mjs";
import type { Logger } from "../../logging/Logger.mjs";
import {
	isTokenBindingMw,
	type TokenBindingMechanism,
	tokenBindingMw,
} from "../../middleware/tokenBinding.mjs";
import { defineModule } from "../../modules/manifest/index.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import type { BootstrapMap } from "../types.mjs";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

interface CapturedWarn {
	readonly obj: Record<string, unknown>;
	readonly msg?: string;
}

function makeCapturingLogger(warns: CapturedWarn[]): Logger {
	const logger: Logger = {
		debug: () => {},
		info: () => {},
		warn: (obj: unknown, msg?: string) => {
			warns.push({ obj: obj as Record<string, unknown>, msg });
		},
		error: () => {},
		child: () => logger,
	} as unknown as Logger;
	return logger;
}

const makeBoot = (logger: Logger): BootstrapMap =>
	({
		config: makeValidCoreConfig() as never,
		pathResolver: (s: string) => s,
		logger,
	}) satisfies Record<string, unknown> as BootstrapMap;

const dpopMech: TokenBindingMechanism = {
	kind: "dpop",
	intentExplicit: true,
	extract: async (_req: Request) => ({ kind: "dpop", confirmation: { jkt: "fake-jkt" } }),
};

const mtlsMech: TokenBindingMechanism = {
	kind: "mtls",
	intentExplicit: false,
	extract: async (_req: Request) => ({
		kind: "mtls",
		confirmation: { "x5t#S256": "fake-thumb" },
	}),
};

/** Module contributing through the current (v0.8+) surface. */
const mechanismModule = (name: string, mechanism: TokenBindingMechanism) =>
	defineModule({
		name,
		requires: [],
		optional: [],
		contributes: { tokenBindingMechanisms: [() => mechanism] },
	});

/** Module contributing a pre-composed `tokenBindingMw` the v0.7 way. */
const legacyTokenBindingModule = (name: string, mechanism: TokenBindingMechanism) =>
	defineModule({
		name,
		requires: [],
		optional: [],
		contributes: {
			grantMiddleware: [
				() => tokenBindingMw({ mechanisms: [mechanism], dispatchPolicy: "intent-explicit" }),
			],
		},
	});

/** Module contributing an ordinary, unrelated `grantMiddleware`. */
const plainGrantMiddlewareModule = (name: string) =>
	defineModule({
		name,
		requires: [],
		optional: [],
		contributes: {
			grantMiddleware: [
				(): RequestHandler => (_req, _res, next) => {
					next();
				},
			],
		},
	});

const routeModule = () =>
	defineModule({
		name: "observer",
		requires: [],
		optional: [],
		contributes: {
			routes: [
				() => {
					const router = Router();
					router.use(express.json());
					router.post("/token", ((_req, res) => {
						res.status(200).json({ ok: true });
					}) as RequestHandler);
					return { id: "test-token", mountPath: "/oauth", handler: router };
				},
			],
		},
	});

const overlapWarnings = (warns: CapturedWarn[]): CapturedWarn[] =>
	warns.filter((w) => w.obj?.reason === "token_binding_surface_overlap");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("isTokenBindingMw", () => {
	it("identifies a handler produced by tokenBindingMw", () => {
		const mw = tokenBindingMw({ mechanisms: [dpopMech], dispatchPolicy: "intent-explicit" });
		expect(isTokenBindingMw(mw)).toBe(true);
	});

	it("is false for an unrelated handler and for non-functions", () => {
		expect(isTokenBindingMw((_req: unknown, _res: unknown, next: () => void) => next())).toBe(
			false,
		);
		expect(isTokenBindingMw(undefined)).toBe(false);
		expect(isTokenBindingMw(null)).toBe(false);
		expect(isTokenBindingMw({})).toBe(false);
		expect(isTokenBindingMw("tokenBindingMw")).toBe(false);
	});
});

describe("token-binding surface overlap — boot warning (#199 I4)", () => {
	it("warns when a grantMiddleware-mounted tokenBindingMw coexists with contributed mechanisms", async () => {
		const warns: CapturedWarn[] = [];
		const handle = await createApp({
			modules: [
				routeModule(),
				mechanismModule("new-surface", dpopMech),
				legacyTokenBindingModule("legacy-surface", mtlsMech),
			],
			bootstrapComponents: makeBoot(makeCapturingLogger(warns)),
		});

		const matched = overlapWarnings(warns);
		expect(matched).toHaveLength(1);
		// The warning must name the offending module so the operator can find
		// the leftover contribution without bisecting their composition root.
		expect(matched[0]?.obj.modules).toEqual(["legacy-surface"]);

		await handle.dispose();
	});

	it("does not warn for an ordinary grantMiddleware alongside mechanisms", async () => {
		const warns: CapturedWarn[] = [];
		const handle = await createApp({
			modules: [
				routeModule(),
				mechanismModule("new-surface", dpopMech),
				plainGrantMiddlewareModule("rate-limiter"),
			],
			bootstrapComponents: makeBoot(makeCapturingLogger(warns)),
		});

		expect(overlapWarnings(warns)).toHaveLength(0);

		await handle.dispose();
	});

	it("does not warn for an un-migrated v0.7 deployment (legacy surface only)", async () => {
		// Nothing is being overridden here — this is simply the pre-migration
		// composition still working as it did. Warning would be noise.
		const warns: CapturedWarn[] = [];
		const handle = await createApp({
			modules: [routeModule(), legacyTokenBindingModule("legacy-surface", mtlsMech)],
			bootstrapComponents: makeBoot(makeCapturingLogger(warns)),
		});

		expect(overlapWarnings(warns)).toHaveLength(0);

		await handle.dispose();
	});
});
