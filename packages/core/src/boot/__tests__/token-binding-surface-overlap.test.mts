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
 * boot/__tests__/token-binding-surface-overlap.test.mts — the boot warning
 * for a `grantMiddleware`-mounted `tokenBindingMw` next to contributed
 * `tokenBindingMechanisms`.
 *
 * `assembleApp` mounts the composed middleware first and `grantMiddleware`
 * contributions after, and `tokenBindingMw` assigns `req.tokenBinding`
 * unguarded, so the legacy middleware wins on every request and the
 * configured `dispatchPolicy` is silently inert. The warning does not fire
 * for a non-token-binding `grantMiddleware` alongside mechanisms, nor for a
 * deployment with no mechanisms at all.
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

/** Module contributing through the `tokenBindingMechanisms` surface. */
const mechanismModule = (name: string, mechanism: TokenBindingMechanism) =>
	defineModule({
		name,
		requires: [],
		optional: [],
		contributes: { tokenBindingMechanisms: [() => mechanism] },
	});

/** Module contributing a pre-composed `tokenBindingMw` through `grantMiddleware`. */
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

/** Module contributing the legacy surface TWICE — one module, two factories. */
const doubleLegacyTokenBindingModule = (name: string, mechanism: TokenBindingMechanism) =>
	defineModule({
		name,
		requires: [],
		optional: [],
		contributes: {
			grantMiddleware: [
				() => tokenBindingMw({ mechanisms: [mechanism], dispatchPolicy: "intent-explicit" }),
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

	it("does not match a brand inherited through the prototype chain", () => {
		// The brand is an own property of the returned handler. Reading it with
		// plain property access would also see one planted on a shared
		// prototype, turning every function in the process into a false
		// positive and filling boot logs with warnings that name innocent
		// modules. Precision is the entire reason the brand exists.
		const brand = Symbol.for("o3co.auth-provider.tokenBindingMw");
		const polluted = Object.create(Function.prototype);
		Object.defineProperty(Object.getPrototypeOf(polluted), brand, {
			value: true,
			configurable: true,
		});
		try {
			const handler = function notTokenBindingMw() {};
			expect(isTokenBindingMw(handler)).toBe(false);
		} finally {
			delete (Function.prototype as unknown as Record<PropertyKey, unknown>)[brand];
		}
	});
});

describe("token-binding surface overlap — boot warning", () => {
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

	it("names a module once even when it contributes the legacy surface twice", async () => {
		// Provenance is collected per contribution, so a module registering two
		// token-binding grantMiddleware factories would otherwise be listed
		// twice — noise in the one field an operator acts on.
		const warns: CapturedWarn[] = [];
		const handle = await createApp({
			modules: [
				routeModule(),
				mechanismModule("new-surface", dpopMech),
				doubleLegacyTokenBindingModule("legacy-surface", mtlsMech),
			],
			bootstrapComponents: makeBoot(makeCapturingLogger(warns)),
		});

		const matched = overlapWarnings(warns);
		expect(matched).toHaveLength(1);
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

	it("does not warn when only the legacy surface is used, with no mechanisms contributed", async () => {
		// With no mechanisms nothing is overridden: a warning would be noise.
		const warns: CapturedWarn[] = [];
		const handle = await createApp({
			modules: [routeModule(), legacyTokenBindingModule("legacy-surface", mtlsMech)],
			bootstrapComponents: makeBoot(makeCapturingLogger(warns)),
		});

		expect(overlapWarnings(warns)).toHaveLength(0);

		await handle.dispose();
	});
});
