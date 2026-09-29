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
 * - It refuses what a browser would drop, as the session store refuses a
 *   `__Host-` name that is not secure and host-only.
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

	it.each([
		[
			"a __Host- name that is not secure",
			{ secure: false },
			/__Host- prefix requires session\.secure=true and session\.domain=null/,
		],
		[
			"a __Host- name with a domain",
			{ domain: "example.com" },
			/__Host- prefix requires session\.secure=true and session\.domain=null/,
		],
		[
			"a __Secure- name that is not secure",
			{ name: "__Secure-auth.session", secure: false },
			/__Secure- prefix requires session\.secure=true/,
		],
		[
			"a cross-site cookie that is not secure",
			{ name: "auth.session", sameSite: "none", secure: false },
			/sameSite = "none" requires session\.secure = true/,
		],
		["a lifetime of no time", { maxAge: 0 }, /session\.maxAge/],
	] as const)("refuses %s, as a browser would drop it", (_what, change, message) => {
		expect(() => sessionCookiePolicyFrom({ ...fixture(), ...change } as SessionSlice)).toThrow(
			message,
		);
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
