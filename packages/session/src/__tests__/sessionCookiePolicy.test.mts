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
 * The session store module's `sessionCookiePolicy` (#728): the session
 * cookie's attributes — name, `secure`, `sameSite`, domain and the session's
 * lifetime — for a module that sets a cookie of its own beside the
 * session's, or sizes what must outlive a session.
 *
 * - It keeps core's contract (`sessionCookiePolicyContract`) over the
 *   configurations the session store accepts: the fixture's `__Host-`
 *   cookie, a cookie scoped to a domain, and one sent cross-site.
 * - It is the cookie express-session is given: the same attributes, and a
 *   `null` domain read as a host-only cookie.
 * - It refuses exactly what the session store refuses of the cookie — a
 *   `__Host-` name that is not secure, or that names a domain, an empty one
 *   included — and nothing more: it is the store's cookie, read as it is.
 *   A `__Secure-` name or a `SameSite=None` cookie that is not secure, which
 *   core's contract holds a policy to, the store does not refuse, and neither
 *   does this (core's schema refuses the second).
 * - The session store module provides it.
 */

import type { AppConfig, SessionCookiePolicy } from "@o3co/auth-provider-core";
import { defineModule } from "@o3co/auth-provider-core";
import {
	createTestApp,
	makeValidAppConfig,
	sessionCookiePolicyContract,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { sessionStoreModuleFor } from "#/modules/sessionStoreModule.mjs";
import { sessionCookiePolicyFrom } from "#/session-cookie-policy.mjs";

type SessionSlice = AppConfig["session"];

const fixture = (): SessionSlice => makeValidAppConfig().session as SessionSlice;

const CONFIGURATIONS: ReadonlyArray<readonly [string, SessionSlice]> = [
	["the fixture's __Host- cookie", fixture()],
	[
		"a cookie scoped to a domain",
		{ ...fixture(), name: "auth.session", domain: "example.com", sameSite: "strict" },
	],
	[
		"a cookie sent cross-site",
		{ ...fixture(), name: "__Secure-auth.session", sameSite: "none", maxAge: 60_000 },
	],
];

describe.each(CONFIGURATIONS)(
	"sessionCookiePolicyFrom keeps core's contract: %s",
	(_what, session) => {
		it.each(sessionCookiePolicyContract({ build: () => sessionCookiePolicyFrom(session) }))(
			"$name",
			async ({ run }) => {
				await run();
			},
		);
	},
);

describe("sessionCookiePolicyFrom", () => {
	it("answers the attributes express-session is given, a null domain as host-only", () => {
		expect(sessionCookiePolicyFrom(fixture())).toEqual({
			name: "__Host-auth.session",
			secure: true,
			sameSite: "lax",
			domain: undefined,
			maxAgeMs: 3_600_000,
		});
		expect(
			sessionCookiePolicyFrom({ ...fixture(), name: "auth.session", domain: "example.com" }).domain,
		).toBe("example.com");
	});

	/** Session sections, each with whether the session store boots with it. */
	const CASES: ReadonlyArray<readonly [string, Partial<SessionSlice>, boolean]> = [
		["a __Host- name that is secure and host-only", {}, true],
		["a __Host- name that is not secure", { secure: false }, false],
		["a __Host- name with a domain", { domain: "example.com" }, false],
		["a __Host- name with an empty domain", { domain: "" }, false],
		["a __Secure- name that is not secure", { name: "__Secure-auth.session", secure: false }, true],
		["a cookie with no prefix and an empty domain", { name: "auth.session", domain: "" }, true],
	];

	it.each(CASES)(
		"%s: refused exactly when the session store refuses it",
		(_what, change, boots) => {
			const session = { ...fixture(), ...change } as SessionSlice;
			if (boots) {
				expect(() => sessionCookiePolicyFrom(session)).not.toThrow();
			} else {
				expect(() => sessionCookiePolicyFrom(session)).toThrow(
					"session.name with __Host- prefix requires session.secure=true and session.domain=null",
				);
			}
		},
	);

	it.each(CASES)("%s: the session store agrees", async (_what, change, boots) => {
		const base = makeValidAppConfig() as AppConfig;
		const config = { ...base, session: { ...base.session, ...change } } as AppConfig;
		const booting = createTestApp({
			modules: [sessionStoreModuleFor(config)],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		if (boots) {
			handles.push(await booting);
		} else {
			await expect(booting).rejects.toThrow(/__Host- prefix requires session\.secure=true/);
		}
	});

	it("does not refuse a cross-site cookie that is not secure: the store does not, and core's schema does, before either is built", () => {
		expect(() =>
			sessionCookiePolicyFrom({
				...fixture(),
				name: "auth.session",
				sameSite: "none",
				secure: false,
			}),
		).not.toThrow();
	});

	it("reads an empty domain as a host-only cookie, as express-session is given it", () => {
		expect(
			sessionCookiePolicyFrom({ ...fixture(), name: "auth.session", domain: "" }).domain,
		).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// The session store module provides it
// ---------------------------------------------------------------------------

const handles: { dispose(): Promise<void> }[] = [];
afterEach(async () => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
});

describe("the session store module provides sessionCookiePolicy", () => {
	it("hands a module that requires it the session cookie's attributes", async () => {
		const seen: { policy?: SessionCookiePolicy } = {};
		const config = makeValidAppConfig() as AppConfig;
		const handle = await createTestApp({
			modules: [
				sessionStoreModuleFor(config),
				defineModule({
					name: "test:session-cookie-policy-consumer",
					requires: ["sessionCookiePolicy"],
					contributes: {
						routes: [
							(deps) => {
								seen.policy = deps.sessionCookiePolicy;
								return { id: "test:probe", mountPath: "/probe", handler: express.Router() };
							},
						],
					},
				}),
			],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		handles.push(handle);
		expect(seen.policy).toEqual(sessionCookiePolicyFrom(config.session));
		expect(Object.isFrozen(seen.policy)).toBe(true);
	});
});
