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
 * The federation callback's login establishes without asking (ADR
 * 2026-09-28-session-admission, D5): core builds its `Establishment` from the
 * federation's own facts (`establishWithoutAsking`), no requirement's
 * `admitPrimary` is consulted, and the record is what
 * `federatedSessionAuthentication` composes. A custom claim whose JSON form
 * cannot be taken is dropped by core and warned on the callback's own logger.
 * The rest of the callback's login is pinned by `Federation.test.mts`.
 */

import {
	codeChallenge,
	type FederationProvider,
	type Logger,
	type PrimaryAuthentication,
	type SessionRequirement,
	type SubjectSessionIndex,
	type User,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { SESSION_ADMISSION_ACTIONS } from "#/admissionActions.mjs";
import { buildFederationApp, makeUserRepository } from "./federation-harness.mjs";

const CALLBACK_URL = "https://app.example.com/session/oauth/federation/test/callback";

/** A query-mode provider whose IdP asserted `amr` of its own. */
const provider: FederationProvider = {
	name: "test",
	scope: ["openid"],
	buildAuthorizationUrl: ({ state, codeVerifier }) => {
		const url = new URL("https://idp.example.com/authorize");
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge", codeChallenge(codeVerifier));
		return url;
	},
	exchangeCode: vi.fn(async () => ({
		issuer: "https://idp.example.com",
		sub: "external-42",
		accessToken: "at",
		expiresAt: new Date(Date.now() + 3_600_000),
		scope: "openid",
		amr: ["otp"],
	})),
};

/** A requirement that interrupts every login it is asked about, recording what it was asked. */
function interruptingEveryLogin(): {
	requirement: SessionRequirement;
	asked: PrimaryAuthentication[];
} {
	const asked: PrimaryAuthentication[] = [];
	return {
		asked,
		requirement: {
			name: "fixture",
			reach: new Set<string>(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
			admitPrimary: async (primary) => {
				asked.push(primary);
				return {
					open: async () => ({ status: 403, body: { error: "fixture_required" } }),
				};
			},
		},
	};
}

describe("the federation callback's login establishes without asking", () => {
	it("is not interrupted by a requirement that would interrupt a password login: the session is established, the requirement never asked", async () => {
		const { requirement, asked } = interruptingEveryLogin();
		const harness = buildFederationApp({
			providers: new Map([["test", provider]]),
			providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
			userRepository: makeUserRepository({
				id: "user-1",
				username: "alice",
				email: "alice@example.com",
			}),
			requirements: resolverForTests([requirement], { actions: SESSION_ADMISSION_ACTIONS }),
		});
		harness.store.set("browser", {
			data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
		});

		const res = await request(harness.app)
			.get("/oauth/federation/test/callback?state=st-1&code=c-1")
			.set("Cookie", "sid=browser");

		expect(res.status).toBe(302);
		expect(asked).toEqual([]);
		expect(harness.userSessionStore.create).toHaveBeenCalledTimes(1);
		const created = harness.userSessionStore.create.mock.calls[0]?.[0] as Record<string, unknown>;
		// What `federatedSessionAuthentication` composes for an untrusted
		// federation (no switch in this config): `fed` alone, the IdP's values
		// kept apart.
		expect(created).toMatchObject({
			sub: "user-1",
			claims: { email: "alice@example.com" },
			amr: ["fed"],
			authentication: {
				primary: "fed",
				federation: "test",
				upstreamAmr: ["otp"],
				mfaAt: undefined,
			},
		});
		// The session is the established one, and carries no `redirectTo`: the
		// callback redirects by its policy and never wrote one.
		const session = harness.store.get("browser")?.data;
		expect(session).toMatchObject({
			isAuthenticated: true,
			sid: created.sid,
			user: { id: "user-1", username: "alice", email: "alice@example.com" },
		});
		expect(session).not.toHaveProperty("redirectTo");
	});
});

describe("the federation callback's login — a user whose field the login needs is not plain data", () => {
	it("answers 500 with nothing written, as the password login does: no record, no index entry, no tokens, no authenticated session", async () => {
		const harness = buildFederationApp({
			providers: new Map([["test", provider]]),
			providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
			// The callback reads the user once with core's `readUserSnapshot`: a
			// field the login needs that is not plain data — a witness that is a
			// Date — is refused there.
			userRepository: makeUserRepository({
				id: "user-1",
				username: "alice",
				mfaEnrolled: new Date(0),
			}),
		});
		harness.store.set("browser", {
			data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
		});

		const res = await request(harness.app)
			.get("/oauth/federation/test/callback?state=st-1&code=c-1")
			.set("Cookie", "sid=browser");

		expect(res.status).toBe(500);
		expect(harness.userSessionStore.create).not.toHaveBeenCalled();
		expect(harness.sessionFederationIndex.addFederation).not.toHaveBeenCalled();
		expect(harness.federationTokenStore.attach).not.toHaveBeenCalled();
		const session = harness.store.get("browser")?.data ?? {};
		for (const field of ["isAuthenticated", "user", "sid"]) {
			expect(session, field).not.toHaveProperty(field);
		}
	});
});

/** A logger that records each line with the bindings of the child that wrote it. */
function recordingLogger(): {
	logger: Logger;
	lines: { level: string; bindings: Record<string, unknown>; args: unknown[] }[];
} {
	const lines: { level: string; bindings: Record<string, unknown>; args: unknown[] }[] = [];
	const make = (bindings: Record<string, unknown>): Logger => {
		const record =
			(level: string) =>
			(...args: unknown[]): void => {
				lines.push({ level, bindings, args });
			};
		return {
			trace: record("trace"),
			debug: record("debug"),
			info: record("info"),
			warn: record("warn"),
			error: record("error"),
			fatal: record("fatal"),
			child: (more: Record<string, unknown>) => make({ ...bindings, ...more }),
		};
	};
	return { logger: make({}), lines };
}

describe("the federation callback's login — a mapped custom claim whose JSON form cannot be taken", () => {
	const cycle = (): Record<string, unknown> => {
		const node: Record<string, unknown> = {};
		node.self = node;
		return node;
	};

	it.each([
		["a bigint", () => ({ tenant: 1n })],
		["a cycle", () => ({ tenant: cycle() })],
	])(
		"holding %s: the session is established without it, and the callback's logger is told once, by key",
		async (_, mapped) => {
			const { logger, lines } = recordingLogger();
			const harness = buildFederationApp({
				providers: new Map<string, FederationProvider>([
					["test", { ...provider, mapClaims: mapped } as FederationProvider],
				]),
				providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
				userRepository: makeUserRepository({
					id: "user-1",
					username: "alice",
					email: "alice@example.com",
				}),
				logger,
			});
			harness.store.set("browser", {
				data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
				cookie: { sameSite: "lax", secure: false, httpOnly: true },
			});

			const res = await request(harness.app)
				.get("/oauth/federation/test/callback?state=st-1&code=c-1")
				.set("Cookie", "sid=browser");

			expect(res.status).toBe(302);
			expect(harness.userSessionStore.create).toHaveBeenCalledTimes(1);
			const created = harness.userSessionStore.create.mock.calls[0]?.[0] as Record<string, unknown>;
			// The mapped claims are recorded under `federated`; that custom claim
			// is the one whose JSON form could not be taken, so it is the one left out.
			expect(created.claims).toEqual({ email: "alice@example.com" });
			expect(harness.store.get("browser")?.data).toMatchObject({
				isAuthenticated: true,
				sid: created.sid,
			});

			const dropped = lines.filter((line) => line.args[1] === "login_claim_dropped");
			expect(dropped).toEqual([
				{
					level: "warn",
					// The callback's per-provider logger, not the router's root one.
					bindings: { provider: "test" },
					// The key and the reason, nothing of the value.
					args: [{ claim: "federated", reason: "unserialisable" }, "login_claim_dropped"],
				},
			]);
		},
	);
});

/** `fields` as a class instance's prototype getters, each counting its reads by name. */
function countingUser(fields: Record<string, unknown>): { user: User; reads: Map<string, number> } {
	const reads = new Map<string, number>();
	class Entity {}
	for (const [name, value] of Object.entries(fields)) {
		Object.defineProperty(Entity.prototype, name, {
			get() {
				reads.set(name, (reads.get(name) ?? 0) + 1);
				return value;
			},
			configurable: true,
		});
	}
	return { user: new Entity() as unknown as User, reads };
}

describe("the federation callback's login — the User the Store answers is read once", () => {
	it("runs each of a getter-backed User's getters exactly once, the subject index's failure line included, and the session's subject and claims are the snapshot's", async () => {
		const { logger, lines } = recordingLogger();
		const { user, reads } = countingUser({
			id: "user-1",
			username: "alice",
			email: "alice@example.com",
			emailVerified: true,
			name: "Alice",
			groups: ["staff"],
			mfaEnrolled: false,
			locale: "en",
		});
		const subjectSessionIndex = {
			kind: "memory",
			addSid: vi.fn(async () => {
				throw new Error("subject index down");
			}),
			listSids: vi.fn(async () => []),
			removeSid: vi.fn(async () => {}),
			removeBySubject: vi.fn(async () => {}),
		} as unknown as SubjectSessionIndex;
		const harness = buildFederationApp({
			providers: new Map([["test", provider]]),
			providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
			userRepository: makeUserRepository(user),
			subjectSessionIndex,
			logger,
		});
		harness.store.set("browser", {
			data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
		});

		const res = await request(harness.app)
			.get("/oauth/federation/test/callback?state=st-1&code=c-1")
			.set("Cookie", "sid=browser");

		expect(res.status).toBe(302);
		for (const field of [
			"id",
			"username",
			"email",
			"emailVerified",
			"name",
			"groups",
			"mfaEnrolled",
		]) {
			expect(reads.get(field), field).toBe(1);
		}
		expect(reads.has("locale")).toBe(false);
		expect(harness.userSessionStore.create).toHaveBeenCalledTimes(1);
		const created = harness.userSessionStore.create.mock.calls[0]?.[0] as Record<string, unknown>;
		expect(created).toMatchObject({
			sub: "user-1",
			claims: {
				email: "alice@example.com",
				emailVerified: true,
				name: "Alice",
				groups: ["staff"],
			},
		});
		const failed = lines.filter((line) => line.args[1] === "subject_session_index_write_failed");
		expect(failed).toHaveLength(1);
		expect(failed[0]?.args[0]).toMatchObject({ sub: "user-1" });
	});
});

describe("the federation callback's login — a User the snapshot refuses", () => {
	it("answers 500 having read each getter once, with nothing written: no record, no index entry of either kind, no tokens, no authenticated session", async () => {
		const { user, reads } = countingUser({
			id: "user-1",
			username: "alice",
			email: "alice@example.com",
			mfaEnrolled: new Date(0),
		});
		const subjectSessionIndex = {
			kind: "memory",
			addSid: vi.fn(async () => {}),
			listSids: vi.fn(async () => []),
			removeSid: vi.fn(async () => {}),
			removeBySubject: vi.fn(async () => {}),
		};
		const harness = buildFederationApp({
			providers: new Map([["test", provider]]),
			providerCallbackUrls: new Map([["test", CALLBACK_URL]]),
			userRepository: makeUserRepository(user),
			subjectSessionIndex: subjectSessionIndex as unknown as SubjectSessionIndex,
		});
		harness.store.set("browser", {
			data: { federation: { name: "test", state: "st-1", codeVerifier: "cv-1" } },
			cookie: { sameSite: "lax", secure: false, httpOnly: true },
		});

		const res = await request(harness.app)
			.get("/oauth/federation/test/callback?state=st-1&code=c-1")
			.set("Cookie", "sid=browser");

		expect(res.status).toBe(500);
		for (const field of ["id", "username", "email", "mfaEnrolled"]) {
			expect(reads.get(field), field).toBe(1);
		}
		expect(harness.userSessionStore.create).not.toHaveBeenCalled();
		expect(harness.sessionFederationIndex.addFederation).not.toHaveBeenCalled();
		expect(subjectSessionIndex.addSid).not.toHaveBeenCalled();
		expect(harness.federationTokenStore.attach).not.toHaveBeenCalled();
		const session = harness.store.get("browser")?.data ?? {};
		for (const field of ["isAuthenticated", "user", "sid"]) {
			expect(session, field).not.toHaveProperty(field);
		}
	});
});
