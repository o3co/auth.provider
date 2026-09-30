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
 * The session store module's `sessionCookiePolicy`: the session cookie's
 * attributes (name, `secure`, `sameSite`, domain, the session's lifetime) for
 * a module that sets a cookie of its own beside the session's, or sizes what
 * must outlive a session. It is the cookie express-session is given, and no
 * session section yields a policy that breaks core's contract. Through
 * createApp a section the policy refuses is refused at validation: by the
 * store's configSchema with the policy's message for a name or a domain, by
 * core's schema first for `SameSite=None` and the lifetime. While the store's
 * module is loaded the slot has no other source.
 */

import type { AppConfig, SessionCookiePolicy } from "@o3co/auth-provider-core";
import { BootError, defineModule, MAX_DURATION_MS } from "@o3co/auth-provider-core";
import {
	createTestApp,
	createTestSessionCookiePolicy,
	makeValidAppConfig,
	sessionCookiePolicyContract,
} from "@o3co/auth-provider-core/testing";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { sessionStoreModule, sessionStoreModuleFor } from "#/modules/sessionStoreModule.mjs";
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

	const HOST_PREFIX =
		"session.name with __Host- prefix requires session.secure=true and session.domain=null";
	const SECURE_PREFIX = "session.name with __Secure- prefix requires session.secure=true";
	const notADomain = (domain: string) =>
		`session.domain ${JSON.stringify(domain)} is not a cookie domain (a host name, one leading dot allowed)`;

	/**
	 * Session sections, each with what the policy refuses it with
	 * (`undefined`: the policy is built).
	 */
	const CASES: ReadonlyArray<readonly [string, Partial<SessionSlice>, string | undefined]> = [
		["a __Host- name that is secure and host-only", {}, undefined],
		["a __Host- name that is not secure", { secure: false }, HOST_PREFIX],
		["a __Host- name with a domain", { domain: "example.com" }, HOST_PREFIX],
		["a __Host- name with an empty domain", { domain: "" }, HOST_PREFIX],
		[
			"a __host- name, in any case, that is not secure",
			{ name: "__host-auth.session", secure: false },
			HOST_PREFIX,
		],
		[
			"a __HOST- name, in any case, with a domain",
			{ name: "__HOST-auth.session", domain: "example.com" },
			HOST_PREFIX,
		],
		[
			"a __HOST- name, in any case, that is secure and host-only",
			{ name: "__HOST-auth.session" },
			undefined,
		],
		[
			"a __Secure- name that is not secure",
			{ name: "__Secure-auth.session", secure: false },
			SECURE_PREFIX,
		],
		[
			"a __SECURE- name, in any case, that is not secure",
			{ name: "__SECURE-auth.session", secure: false },
			SECURE_PREFIX,
		],
		[
			"a name that is not a cookie name",
			{ name: "auth session" },
			'session.name "auth session" is not a cookie name (an RFC 6265 token)',
		],
		[
			"a cookie with no prefix and an empty domain",
			{ name: "auth.session", domain: "" },
			undefined,
		],
		["a domain after a leading dot", { name: "auth.session", domain: ".example.com" }, undefined],
		[
			"a domain that is a URL",
			{ name: "auth.session", domain: "https://auth.example.com" },
			notADomain("https://auth.example.com"),
		],
		[
			"a domain with a port",
			{ name: "auth.session", domain: "auth.example.com:8443" },
			notADomain("auth.example.com:8443"),
		],
		[
			"a domain with an empty label",
			{ name: "auth.session", domain: "example..com" },
			notADomain("example..com"),
		],
		[
			"a domain whose label starts with a hyphen",
			{ name: "auth.session", domain: "-example.com" },
			notADomain("-example.com"),
		],
	];

	it.each(CASES)("%s: the policy refuses it as the column says", (_what, change, refusal) => {
		const session = { ...fixture(), ...change } as SessionSlice;
		if (refusal === undefined) {
			expect(() => sessionCookiePolicyFrom(session)).not.toThrow();
		} else {
			expect(() => sessionCookiePolicyFrom(session)).toThrow(refusal);
		}
	});

	it.each(CASES)(
		"%s: the session store boots with it exactly when the policy is built, and refuses it at validation with the policy's message",
		async (_what, change, refusal) => {
			const base = makeValidAppConfig() as AppConfig;
			const config = { ...base, session: { ...base.session, ...change } } as AppConfig;
			const booting = createTestApp({
				modules: [sessionStoreModuleFor(config)],
				bootstrapComponents: { config, pathResolver: (s: string) => s },
			});
			if (refusal === undefined) {
				handles.push(await booting);
			} else {
				await expect(booting).rejects.toMatchObject({
					reason: "config-validation-failed",
					stage: "validateManifests",
					details: { issues: [{ message: refusal }] },
				});
			}
		},
	);

	it("refuses a cross-site cookie that is not secure, which core's schema refuses before it is built", () => {
		expect(() =>
			sessionCookiePolicyFrom({
				...fixture(),
				name: "auth.session",
				sameSite: "none",
				secure: false,
			}),
		).toThrow('session.sameSite = "none" requires session.secure = true');
	});

	it.each([0, -1, 1.5, MAX_DURATION_MS + 1, Number.NaN])(
		"refuses a lifetime of %s, which core's schema refuses before it is built",
		(maxAge) => {
			expect(() => sessionCookiePolicyFrom({ ...fixture(), maxAge })).toThrow(
				`session.maxAge must be a whole number of milliseconds from 1 to ${MAX_DURATION_MS}`,
			);
		},
	);

	it("builds a lifetime of 1 and of the ceiling", () => {
		expect(sessionCookiePolicyFrom({ ...fixture(), maxAge: 1 }).maxAgeMs).toBe(1);
		expect(sessionCookiePolicyFrom({ ...fixture(), maxAge: MAX_DURATION_MS }).maxAgeMs).toBe(
			MAX_DURATION_MS,
		);
	});

	it("yields no policy that breaks core's contract, over every combination of the cookie's attributes", async () => {
		const names = [
			"__Host-auth.session",
			"__host-auth.session",
			"__Secure-auth.session",
			"__SECURE-auth.session",
			"auth.session",
			"auth session",
			"auth;session",
			"",
		];
		const broken: string[] = [];
		for (const name of names) {
			for (const secure of [true, false]) {
				for (const sameSite of ["lax", "strict", "none"] as const) {
					for (const domain of [null, "", "example.com", ".example.com", "https://example.com"]) {
						for (const maxAge of [3_600_000, 0, 1.5, MAX_DURATION_MS + 1]) {
							const session = { ...fixture(), name, secure, sameSite, domain, maxAge };
							let policy: SessionCookiePolicy;
							try {
								policy = sessionCookiePolicyFrom(session);
							} catch {
								continue;
							}
							for (const { name: rule, run } of sessionCookiePolicyContract({
								build: () => policy,
							})) {
								try {
									await run();
								} catch {
									broken.push(
										`${JSON.stringify({ name, secure, sameSite, domain, maxAge })}: ${rule}`,
									);
								}
							}
						}
					}
				}
			}
		}
		expect(broken).toEqual([]);
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

/** A module that requires the slot, and keeps what it was handed. */
const consumer = (seen: { policy?: SessionCookiePolicy }) =>
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
	});

/** What a boot settles as: the refusal, or `undefined` once it booted and was disposed. */
const settled = (boot: Promise<{ dispose(): Promise<void> }>): Promise<unknown> =>
	boot.then(
		async (handle) => {
			await handle.dispose();
			return undefined;
		},
		(err: unknown) => err,
	);

describe("the session store module provides sessionCookiePolicy", () => {
	it("hands a module that requires it the session cookie's attributes", async () => {
		const seen: { policy?: SessionCookiePolicy } = {};
		const config = makeValidAppConfig() as AppConfig;
		const handle = await createTestApp({
			modules: [sessionStoreModuleFor(config), consumer(seen)],
			bootstrapComponents: { config, pathResolver: (s: string) => s },
		});
		handles.push(handle);
		expect(seen.policy).toEqual(sessionCookiePolicyFrom(config.session));
		expect(Object.isFrozen(seen.policy)).toBe(true);
	});

	it.each([
		["sessionStoreModuleFor(config)", (config: AppConfig) => sessionStoreModuleFor(config)],
		["sessionStoreModule", () => sessionStoreModule],
	] as const)(
		"%s: a section it refuses is refused at validation, whether or not a module requires the slot",
		async (_form, form) => {
			const base = makeValidAppConfig() as AppConfig;
			const config = { ...base, session: { ...base.session, name: "auth session" } } as AppConfig;
			const message = 'session.name "auth session" is not a cookie name (an RFC 6265 token)';
			for (const readers of [[], [consumer({})]]) {
				expect(
					await settled(
						createTestApp({
							modules: [form(config), ...readers],
							bootstrapComponents: { config, pathResolver: (s: string) => s },
						}),
					),
				).toMatchObject({
					name: "BootError",
					reason: "config-validation-failed",
					stage: "validateManifests",
					details: {
						reason: "config-validation-failed",
						issues: [{ code: "custom", path: ["session", "name"], message }],
					},
				});
			}
		},
	);
});

describe("the session store module names sessionCookiePolicy authoritative", () => {
	/** A policy that differs from the section's, as a second source would. */
	const SECOND = createTestSessionCookiePolicy({ name: "__Host-second.session" });

	const FORMS = [
		["sessionStoreModuleFor(config)", (config: AppConfig) => sessionStoreModuleFor(config)],
		["sessionStoreModule", () => sessionStoreModule],
	] as const;

	it.each(FORMS)("%s names it, and nothing else it provides", (_form, form) => {
		expect(form(makeValidAppConfig() as AppConfig).authoritative).toEqual(["sessionCookiePolicy"]);
	});

	it.each(FORMS)(
		"%s: an override of the slot refuses boot, naming the module and the key, whether or not a module requires it",
		async (_form, form) => {
			const config = makeValidAppConfig() as AppConfig;
			for (const readers of [[], [consumer({})]]) {
				const caught = await settled(
					createTestApp({
						modules: [form(config), ...readers],
						bootstrapComponents: { config, pathResolver: (s: string) => s },
						overrideComponents: { sessionCookiePolicy: SECOND },
					}),
				);
				expect(caught).toBeInstanceOf(BootError);
				expect((caught as BootError).reason).toBe("authoritative-component-overridden");
				expect((caught as BootError).details).toEqual({
					reason: "authoritative-component-overridden",
					module: "session-store",
					componentKey: "sessionCookiePolicy",
				});
			}
		},
	);

	it.each(["overrideComponents", "bootstrapComponents"] as const)(
		"lets a composition without the module fill the slot itself, through %s",
		async (map) => {
			const seen: { policy?: SessionCookiePolicy } = {};
			const config = makeValidAppConfig() as AppConfig;
			const handle = await createTestApp({
				modules: [consumer(seen)],
				bootstrapComponents: {
					config,
					pathResolver: (s: string) => s,
					...(map === "bootstrapComponents" ? { sessionCookiePolicy: SECOND } : {}),
				},
				...(map === "overrideComponents"
					? { overrideComponents: { sessionCookiePolicy: SECOND } }
					: {}),
			});
			handles.push(handle);
			expect(seen.policy).toBe(SECOND);
		},
	);
});
