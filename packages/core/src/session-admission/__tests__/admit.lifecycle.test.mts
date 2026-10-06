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
 * Admission's read of the session lifecycle: after the live record, the
 * lifecycle port's record for its sid — one closing or closed, or none,
 * is `not_live` (`closing`); a user-session store handed without one is
 * `unavailable` (`session_lifecycle`), as is a store that cannot answer, or
 * answers outside its types.
 */

import { describe, expect, it } from "vitest";
import type { AuditEvent } from "#/audit/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import { admitSession, cookieClaim, tokenClaim } from "#/session-admission/admit.mjs";
import type {
	AdmissionDeps,
	AdmissionRequest,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import {
	ADMISSION_INFRASTRUCTURE_STORES,
	describeAdmissionOutage,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import { createInMemorySessionLifecycleStore } from "#/user-sessions/lifecycle/memory.mjs";
import type { SessionLifecycleStore } from "#/user-sessions/lifecycle/types.mjs";
import type { UserSession, UserSessionStore } from "#/user-sessions/types.mjs";
import { TEST_ACTIONS } from "./actions.fixture.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");
const SID = "sid-1";
const SUB = "user-1";
const EXPIRES_AT = new Date(NOW.getTime() + 3_600_000);

const record: UserSession = {
	sid: SID,
	sub: SUB,
	authTime: new Date(NOW.getTime() - 300_000),
	createdAt: new Date(NOW.getTime() - 300_000),
	expiresAt: EXPIRES_AT,
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
};

const userSessionStore: UserSessionStore = {
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === SID ? record : null),
	delete: async () => {},
};

const lines: { level: string; message: string | undefined; fields: Record<string, unknown> }[] = [];
const logger = {
	trace: () => {},
	debug: () => {},
	info: () => {},
	warn: (fields: Record<string, unknown>, message?: string) =>
		lines.push({ level: "warn", message, fields }),
	error: (fields: Record<string, unknown>, message?: string) =>
		lines.push({ level: "error", message, fields }),
	fatal: () => {},
	child: () => logger,
} as unknown as Logger;

const deps = (over: Partial<AdmissionDeps> = {}): AdmissionDeps => ({
	userSessionStore,
	sessionLifecycleStore: undefined,
	subjectRevocation: undefined,
	requirements: resolverForTests([], { actions: TEST_ACTIONS }),
	acrTable: readAcrTable({}),
	logger,
	auditSink: undefined,
	now: () => NOW,
	...over,
});

const cookie = (): AdmissionRequest => ({
	claim: cookieClaim({ session: { isAuthenticated: true, sid: SID, user: { id: SUB } } }),
	action: "test.use",
});

/** A lifecycle store on admission's clock, the session opened in it. */
const lifecycle = async (): Promise<SessionLifecycleStore> => {
	const store = createInMemorySessionLifecycleStore({ now: () => NOW.getTime() });
	expect((await store.open(SID, SUB, EXPIRES_AT)).outcome).toBe("opened");
	return store;
};

const close = (store: SessionLifecycleStore, steps: readonly string[]) =>
	store.beginClose(SID, { cause: "rp_logout", steps, perParticipant: [], retainMs: 0 });

describe("admission's read of the session lifecycle", () => {
	it("admits a session whose lifecycle record is active", async () => {
		const store = await lifecycle();
		expect((await admitSession(deps({ sessionLifecycleStore: store }), cookie())).outcome).toBe(
			"admitted",
		);
	});

	it("is not_live (closing) from the closing commit on, the user session still there", async () => {
		const store = await lifecycle();
		expect((await close(store, ["delete_user_session"])).outcome).toBe("closing");
		expect(await admitSession(deps({ sessionLifecycleStore: store }), cookie())).toEqual({
			outcome: "not_live",
			reason: "closing",
		});
	});

	it("is not_live (closing) once the record is closed", async () => {
		const store = await lifecycle();
		expect((await close(store, [])).outcome).toBe("closed");
		expect(await admitSession(deps({ sessionLifecycleStore: store }), cookie())).toEqual({
			outcome: "not_live",
			reason: "closing",
		});
	});

	it("is not_live (closing) for a token carrier naming a closing session", async () => {
		const store = await lifecycle();
		await close(store, ["delete_user_session"]);
		const token: AdmissionRequest = {
			claim: tokenClaim({ sid: SID, sub: SUB, amr: ["pwd"] }),
			action: "test.use",
		};
		expect(await admitSession(deps({ sessionLifecycleStore: store }), token)).toEqual({
			outcome: "not_live",
			reason: "closing",
		});
	});

	it("is not_live (closing) for a session with no lifecycle record: an absent record reads as closed", async () => {
		const store = createInMemorySessionLifecycleStore({ now: () => NOW.getTime() });
		expect(await admitSession(deps({ sessionLifecycleStore: store }), cookie())).toEqual({
			outcome: "not_live",
			reason: "closing",
		});
	});

	it("is not_live (closing) for a token carrier naming a session with no lifecycle record", async () => {
		const store = createInMemorySessionLifecycleStore({ now: () => NOW.getTime() });
		const token: AdmissionRequest = {
			claim: tokenClaim({ sid: SID, sub: SUB, amr: ["pwd"] }),
			action: "test.use",
		};
		expect(await admitSession(deps({ sessionLifecycleStore: store }), token)).toEqual({
			outcome: "not_live",
			reason: "closing",
		});
	});

	it("is unavailable (session_lifecycle) where a user-session store is handed and no lifecycle store, logged once", async () => {
		lines.length = 0;
		expect(await admitSession(deps({ sessionLifecycleStore: undefined }), cookie())).toEqual({
			outcome: "unavailable",
			store: "session_lifecycle",
		});
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "session_lifecycle", action: "test.use" },
		});
	});

	it("reads no lifecycle where no user-session store is handed", async () => {
		const token: AdmissionRequest = {
			claim: tokenClaim({ sid: SID, sub: SUB, amr: ["pwd"] }),
			action: "test.use",
		};
		expect(
			(
				await admitSession(
					deps({ userSessionStore: undefined, sessionLifecycleStore: undefined }),
					token,
				)
			).outcome,
		).toBe("admitted");
	});

	it("does not read the lifecycle when the user session is gone", async () => {
		let reads = 0;
		const store = await lifecycle();
		const counting: SessionLifecycleStore = {
			...store,
			read: async (sid) => {
				reads += 1;
				return store.read(sid);
			},
		};
		const gone: UserSessionStore = { ...userSessionStore, get: async () => null };
		expect(
			await admitSession(
				deps({ userSessionStore: gone, sessionLifecycleStore: counting }),
				cookie(),
			),
		).toEqual({ outcome: "not_live", reason: "gone" });
		expect(reads).toBe(0);
	});

	it("is unavailable (session_lifecycle) for a store that throws or answers outside its types, logged once", async () => {
		const store = await lifecycle();
		for (const read of [
			async () => {
				throw new Error("lifecycle store down");
			},
			async () => ({ value: { state: "gone" }, generation: "g" }),
		]) {
			lines.length = 0;
			expect(
				await admitSession(
					deps({ sessionLifecycleStore: { ...store, read: read as never } }),
					cookie(),
				),
			).toEqual({ outcome: "unavailable", store: "session_lifecycle" });
			expect(lines).toHaveLength(1);
			expect(lines[0]).toMatchObject({
				level: "error",
				message: "session_admission_unavailable",
				fields: { store: "session_lifecycle", action: "test.use" },
			});
		}
	});

	it("refuses a closing session whose cookie names another subject as the subject mismatch, audited, reading no lifecycle", async () => {
		let reads = 0;
		const store = await lifecycle();
		await close(store, ["delete_user_session"]);
		const counting: SessionLifecycleStore = {
			...store,
			read: async (sid) => {
				reads += 1;
				return store.read(sid);
			},
		};
		const events: AuditEvent[] = [];
		lines.length = 0;
		const answer = await admitSession(
			deps({
				sessionLifecycleStore: counting,
				auditSink: { kind: "test", record: async (event) => void events.push(event) },
			}),
			{
				claim: cookieClaim({
					session: { isAuthenticated: true, sid: SID, user: { id: "someone-else" } },
				}),
				action: "test.use",
			},
		);
		await new Promise((resolve) => setImmediate(resolve));
		expect(answer).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(lines.map((line) => line.message)).toEqual(["session_admission_subject_mismatch"]);
		expect(events.map((event) => event.type)).toEqual(["session.admission.subject_mismatch"]);
		expect(reads).toBe(0);
	});

	it("is unavailable (session_lifecycle) for a lifecycle record of another subject", async () => {
		const store = createInMemorySessionLifecycleStore({ now: () => NOW.getTime() });
		expect((await store.open(SID, "another-user", EXPIRES_AT)).outcome).toBe("opened");
		lines.length = 0;
		expect(await admitSession(deps({ sessionLifecycleStore: store }), cookie())).toEqual({
			outcome: "unavailable",
			store: "session_lifecycle",
		});
		expect(lines).toHaveLength(1);
	});

	it("answers the last reading's not_live (closing) when a close commits while a requirement is asked", async () => {
		let reads = 0;
		const store = await lifecycle();
		const counting: SessionLifecycleStore = {
			...store,
			read: async (sid) => {
				reads += 1;
				return store.read(sid);
			},
		};
		const closing: SessionRequirement = {
			name: "pending",
			reach: new Set(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: async () => {
				// The close commits while the requirement is being asked.
				await close(store, ["delete_user_session"]);
				return { outcome: "met" };
			},
		};
		const answer = await admitSession(
			deps({
				sessionLifecycleStore: counting,
				requirements: resolverForTests([closing], { actions: TEST_ACTIONS, allowAnyReach: true }),
			}),
			cookie(),
		);
		expect(answer).toEqual({ outcome: "not_live", reason: "closing" });
		expect(reads).toBe(2);
	});

	it("is unavailable (session_lifecycle) when reading the store off deps throws — never a rejection", async () => {
		const throwing = {
			...deps(),
			get sessionLifecycleStore(): SessionLifecycleStore {
				throw new Error("deps down");
			},
		};
		lines.length = 0;
		expect(await admitSession(throwing, cookie())).toEqual({
			outcome: "unavailable",
			store: "session_lifecycle",
		});
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "session_lifecycle", action: "test.use" },
		});
	});

	it("names the lifecycle store among admission's own, and words its outage", () => {
		expect(ADMISSION_INFRASTRUCTURE_STORES).toContain("session_lifecycle");
		expect(describeAdmissionOutage("session_lifecycle")).toBe(
			"session lifecycle store unavailable",
		);
	});
});
