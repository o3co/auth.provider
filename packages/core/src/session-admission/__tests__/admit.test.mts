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
 * `admitSession` (the session-admission ADR's D2, D4, D10): the claim
 * builders, the seven steps in order and fail-closed, the graded action and
 * the `remediation` rule, the two log lines, the audit event, and the brands
 * a caller cannot forge. The merge's rows are `admit.merge.test.mts`.
 */

import { describe, expect, it } from "vitest";
import type { AuditEvent, AuditSink } from "#/audit/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	ADMISSION_ACTIONS,
	admitSession,
	codeClaim,
	cookieClaim,
	linkClaim,
	tokenClaim,
} from "#/session-admission/admit.mjs";
import type {
	AdmissionDeps,
	AdmissionRequest,
	RequirementInput,
	SessionClaim,
	SessionRequirement,
	SessionRequirementResolver,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import type { SubjectRevocation, UserSession, UserSessionStore } from "#/user-sessions/types.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");
const minutesAgo = (minutes: number): Date => new Date(NOW.getTime() - minutes * 60_000);

const session = (over: Partial<UserSession> = {}): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: minutesAgo(5),
	createdAt: minutesAgo(5),
	expiresAt: new Date(NOW.getTime() + 3_600_000),
	claims: {},
	amr: ["pwd"],
	authentication: {
		primary: "pwd",
		federation: undefined,
		upstreamAmr: undefined,
		mfaAt: undefined,
	},
	...over,
});

const storeOf = (
	answer: (sid: string) => Promise<UserSession | null | undefined>,
): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: answer as UserSessionStore["get"],
	delete: async () => {},
});

const holding = (record: UserSession): UserSessionStore =>
	storeOf(async (sid) => (sid === record.sid ? record : null));

const revocationOf = (answer: (subject: string) => Promise<unknown>): SubjectRevocation => ({
	kind: "test",
	revokeBefore: async () => {},
	revokedBefore: answer as SubjectRevocation["revokedBefore"],
});

interface Line {
	readonly level: "info" | "warn" | "error";
	readonly fields: Record<string, unknown>;
	readonly message: string | undefined;
}

const recordingLogger = (): { readonly logger: Logger; readonly lines: Line[] } => {
	const lines: Line[] = [];
	const at =
		(level: Line["level"]) =>
		(first: unknown, second?: unknown): void => {
			lines.push({
				level,
				fields:
					typeof first === "object" && first !== null ? (first as Record<string, unknown>) : {},
				message: typeof first === "string" ? first : (second as string | undefined),
			});
		};
	const logger = {
		trace: () => {},
		debug: () => {},
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
		fatal: () => {},
		child: () => logger,
	} as unknown as Logger;
	return { logger, lines };
};

const recordingSink = (): { readonly sink: AuditSink; readonly events: AuditEvent[] } => {
	const events: AuditEvent[] = [];
	return {
		sink: {
			record: async (event) => {
				events.push(event);
			},
		},
		events,
	};
};

const cookie = (over: Record<string, unknown> = {}): SessionClaim =>
	cookieClaim({
		session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" }, ...over },
	});

const met = (name: string, over: Partial<SessionRequirement> = {}): SessionRequirement => ({
	name,
	reach: new Set(),
	stepUpPage: undefined,
	remediations: [],
	hintKeys: [],
	admit: async () => ({ outcome: "met" }),
	...over,
});

const deps = (over: Partial<AdmissionDeps> = {}): AdmissionDeps => ({
	userSessionStore: holding(session()),
	subjectRevocation: undefined,
	requirements: resolverForTests([]),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
	now: () => NOW,
	...over,
});

const request = (over: Partial<AdmissionRequest> = {}): AdmissionRequest => ({
	claim: cookie(),
	action: ADMISSION_ACTIONS["oauth.authorize"],
	...over,
});

const flush = () => new Promise((resolve) => setImmediate(resolve));

describe("the claim builders — one reading of each carrier (D2)", () => {
	it("reads a cookie: authenticated only when isAuthenticated is exactly true, sid and user.id when they are non-empty strings", () => {
		expect(cookie()).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "cookie",
		});
		for (const flag of [1, "true", undefined, null, {}]) {
			expect(cookie({ isAuthenticated: flag }).authenticated, String(flag)).toBe(false);
		}
		for (const sid of ["", 7, null, undefined]) {
			expect(cookie({ sid }).sid, String(sid)).toBeUndefined();
		}
		for (const user of [undefined, null, {}, { id: "" }, { id: 7 }, "user-1"]) {
			expect(cookie({ user }).subject, JSON.stringify(user)).toBeUndefined();
		}
		expect(cookieClaim({ session: undefined })).toMatchObject({
			authenticated: false,
			sid: undefined,
			subject: undefined,
		});
		expect(cookieClaim({})).toMatchObject({ authenticated: false });
	});

	it("reads a code record: authenticated, the code's sid, and no subject unless the first read's is handed in", () => {
		expect(codeClaim({ sid: "sid-1" })).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: undefined,
			carrier: "code",
		});
		expect(codeClaim({ sid: "sid-1" }, { subject: "user-1" })).toMatchObject({
			subject: "user-1",
		});
		expect(codeClaim({}).sid).toBeUndefined();
		expect(codeClaim({ sid: "" }).sid).toBeUndefined();
	});

	it("reads a link transaction: authenticated, its sid and the subject recorded at the start", () => {
		expect(linkClaim({ sid: "sid-1", subject: "user-1" })).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "link",
		});
	});

	it("reads a verified token: authenticated, its sid when it carries one, its sub, and its amr when well formed", () => {
		expect(tokenClaim({ sid: "sid-1", sub: "user-1", amr: ["pwd", "otp", "mfa"] })).toMatchObject({
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "token",
			tokenAmr: ["pwd", "otp", "mfa"],
		});
		expect(tokenClaim({ sub: "user-1" })).toMatchObject({ sid: undefined, subject: "user-1" });
		expect(tokenClaim({ sub: "user-1" })).not.toHaveProperty("tokenAmr");
		// A token issued before #481, or one whose amr is not a well-formed list.
		for (const amr of [undefined, [], [""], "pwd", [1]]) {
			expect(tokenClaim({ sub: "user-1", amr }), JSON.stringify(amr)).not.toHaveProperty(
				"tokenAmr",
			);
		}
		expect(() => tokenClaim({ sub: "" })).toThrow(RangeError);
		expect(() => tokenClaim({ sid: "sid-1" } as never)).toThrow(RangeError);
	});

	it("refuses, before anything is read, what is not a carrier: a caller's fault is a RangeError", () => {
		for (const bad of [undefined, null, "cookie", 7]) {
			expect(() => cookieClaim(bad as never), String(bad)).toThrow(RangeError);
			expect(() => codeClaim(bad as never), String(bad)).toThrow(RangeError);
			expect(() => linkClaim(bad as never), String(bad)).toThrow(RangeError);
			expect(() => tokenClaim(bad as never), String(bad)).toThrow(RangeError);
		}
		expect(() => codeClaim({ sid: "sid-1" }, { subject: "" })).toThrow(RangeError);
		expect(() => codeClaim({ sid: "sid-1" }, { subject: 7 as never })).toThrow(RangeError);
		expect(() => linkClaim({ sid: "", subject: "user-1" })).toThrow(RangeError);
		expect(() => linkClaim({ sid: "sid-1", subject: "" })).toThrow(RangeError);
	});

	it("answers a frozen claim", () => {
		expect(Object.isFrozen(cookie())).toBe(true);
		expect(Object.isFrozen(codeClaim({ sid: "sid-1" }))).toBe(true);
		expect(Object.isFrozen(linkClaim({ sid: "sid-1", subject: "user-1" }))).toBe(true);
	});
});

describe("what admitSession refuses before it reads anything (a caller's fault is a RangeError)", () => {
	it("refuses a claim that a builder did not make, however well it is shaped", async () => {
		const forged = {
			authenticated: true,
			sid: "sid-1",
			subject: "user-1",
			carrier: "cookie",
		} as unknown as SessionClaim;
		await expect(admitSession(deps(), request({ claim: forged }))).rejects.toThrow(RangeError);
		const copy = { ...cookie() } as SessionClaim;
		await expect(admitSession(deps(), request({ claim: copy }))).rejects.toThrow(RangeError);
	});

	it("refuses a resolver the planner or resolverForTests did not build", async () => {
		const forged = {
			get: () => undefined,
			entries: () => [][Symbol.iterator](),
		} as unknown as SessionRequirementResolver;
		await expect(admitSession(deps({ requirements: forged }), request())).rejects.toThrow(
			RangeError,
		);
		await expect(
			admitSession(deps({ requirements: undefined as never }), request()),
		).rejects.toThrow(RangeError);
	});

	it("refuses an action that is not a name with a grade", async () => {
		for (const action of [
			undefined,
			null,
			"oauth.authorize",
			{ name: "", grade: "use" },
			{ name: "x", grade: "strict" },
			{ name: 7, grade: "use" },
			{ grade: "use" },
		]) {
			await expect(
				admitSession(deps(), request({ action: action as never })),
				JSON.stringify(action),
			).rejects.toThrow(RangeError);
		}
	});

	it("refuses asks that are not a list of acr values, and a table that is not one", async () => {
		for (const acrValues of ["urn:x", [7], [""], null]) {
			await expect(
				admitSession(deps(), request({ asks: { acrValues: acrValues as never } })),
				JSON.stringify(acrValues),
			).rejects.toThrow(RangeError);
		}
		await expect(admitSession(deps({ acrTable: null as never }), request())).rejects.toThrow(
			RangeError,
		);
	});

	it("reads nothing when it refuses: the store is not asked", async () => {
		let asked = 0;
		const store = storeOf(async () => {
			asked++;
			return session();
		});
		await expect(
			admitSession(deps({ userSessionStore: store }), request({ action: {} as never })),
		).rejects.toThrow(RangeError);
		expect(asked).toBe(0);
	});
});

describe("step 1 — the claim", () => {
	it("answers unauthenticated for a claim that is not authenticated, reading no store", async () => {
		let asked = 0;
		const store = storeOf(async () => {
			asked++;
			return session();
		});
		expect(
			await admitSession(
				deps({ userSessionStore: store }),
				request({ claim: cookie({ isAuthenticated: false }) }),
			),
		).toEqual({ outcome: "unauthenticated" });
		expect(asked).toBe(0);
	});

	it("answers not_live (subject_mismatch) for a cookie without a subject: the three consumers that refuse it keep doing so, and the two that did not join them", async () => {
		expect(await admitSession(deps(), request({ claim: cookie({ user: undefined }) }))).toEqual({
			outcome: "not_live",
			reason: "subject_mismatch",
		});
	});

	it("does not ask a subject of a code claim's first read, which has none", async () => {
		expect(
			await admitSession(deps(), request({ claim: codeClaim({ sid: "sid-1" }) })),
		).toMatchObject({ outcome: "admitted" });
	});
});

describe("step 2 — the live read", () => {
	it("answers not_live (no_sid) with a store and no sid", async () => {
		expect(await admitSession(deps(), request({ claim: cookie({ sid: undefined }) }))).toEqual({
			outcome: "not_live",
			reason: "no_sid",
		});
	});

	it("skips the read for a token without a sid, as the refresh grant does today: the session is null and the requirements decide", async () => {
		let asked = 0;
		const seen: RequirementInput[] = [];
		const store = storeOf(async () => {
			asked++;
			return session();
		});
		const watching = met("watch", {
			admit: async (input) => {
				seen.push(input);
				return { outcome: "met" };
			},
		});
		expect(
			await admitSession(
				deps({ userSessionStore: store, requirements: resolverForTests([watching]) }),
				request({ claim: tokenClaim({ sub: "user-1", amr: ["pwd"] }) }),
			),
		).toEqual({ outcome: "admitted", session: null, acr: undefined });
		expect(asked).toBe(0);
		expect(seen[0]).toMatchObject({ session: null, carrier: "token" });
	});

	it("reads the record for a token with a sid, and compares its sub", async () => {
		expect(
			await admitSession(deps(), request({ claim: tokenClaim({ sid: "sid-1", sub: "user-1" }) })),
		).toMatchObject({ outcome: "admitted", session: session() });
		expect(
			await admitSession(deps(), request({ claim: tokenClaim({ sid: "sid-1", sub: "user-2" }) })),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(
			await admitSession(deps(), request({ claim: tokenClaim({ sid: "sid-9", sub: "user-1" }) })),
		).toEqual({ outcome: "not_live", reason: "gone" });
	});

	it("answers not_live (gone) for a store that answers null or undefined", async () => {
		for (const answer of [null, undefined]) {
			expect(
				await admitSession(deps({ userSessionStore: storeOf(async () => answer) }), request()),
				String(answer),
			).toEqual({ outcome: "not_live", reason: "gone" });
		}
	});

	it("answers not_live (gone) for a record whose sub is not a non-empty string", async () => {
		for (const sub of ["", undefined, 7]) {
			expect(
				await admitSession(
					deps({ userSessionStore: holding(session({ sub: sub as never })) }),
					request({ claim: codeClaim({ sid: "sid-1" }) }),
				),
				String(sub),
			).toEqual({ outcome: "not_live", reason: "gone" });
		}
	});

	it("answers not_live (gone) for a record whose expiresAt is not later than now: the port does not promise that get filters expiry", async () => {
		for (const expiresAt of [NOW, minutesAgo(1), new Date(Number.NaN), undefined, "later"]) {
			expect(
				await admitSession(
					deps({ userSessionStore: holding(session({ expiresAt: expiresAt as never })) }),
					request(),
				),
				String(expiresAt),
			).toEqual({ outcome: "not_live", reason: "gone" });
		}
		expect(
			await admitSession(
				deps({ userSessionStore: holding(session({ expiresAt: new Date(NOW.getTime() + 1) })) }),
				request(),
			),
		).toMatchObject({ outcome: "admitted" });
	});

	it("answers unavailable (user_session) when the store throws, logged once at error with the store, the action and the projection — never the sid", async () => {
		const { logger, lines } = recordingLogger();
		const failure = Object.assign(new Error("ECONNRESET sid-1"), { command: { args: ["sid-1"] } });
		expect(
			await admitSession(
				deps({
					userSessionStore: storeOf(async () => {
						throw failure;
					}),
					logger,
				}),
				request(),
			),
		).toEqual({ outcome: "unavailable", store: "user_session" });
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "user_session", action: "oauth.authorize" },
		});
		expect(lines[0]?.fields.err).toMatchObject({ name: "Error" });
		expect(lines[0]?.fields.err).not.toBe(failure);
		expect(JSON.stringify(lines[0]?.fields)).not.toContain('"sid"');
		expect(JSON.stringify(lines[0]?.fields)).not.toContain("args");
	});

	it("reads no session without a store: the requirements decide what null means, and with none registered a cookie-only composition is admitted", async () => {
		const seen: RequirementInput[] = [];
		const watching = met("watch", {
			admit: async (input) => {
				seen.push(input);
				return { outcome: "met" };
			},
		});
		expect(
			await admitSession(
				deps({ userSessionStore: undefined, requirements: resolverForTests([watching]) }),
				request(),
			),
		).toEqual({ outcome: "admitted", session: null, acr: undefined });
		expect(seen).toHaveLength(1);
		expect(seen[0]).toMatchObject({ session: null, authentication: null });
	});

	it("answers the live record itself on admitted", async () => {
		const record = session();
		const admission = await admitSession(deps({ userSessionStore: holding(record) }), request());
		expect(admission).toEqual({ outcome: "admitted", session: record, acr: undefined });
	});
});

describe("step 3 — the subject", () => {
	it("answers not_live (subject_mismatch) when the claim's subject is not the record's, logged once at warn with the action and no identifier, and audited with the sid and both subjects", async () => {
		const { logger, lines } = recordingLogger();
		const { sink, events } = recordingSink();
		expect(
			await admitSession(
				deps({ logger, auditSink: sink }),
				request({ claim: cookie({ user: { id: "user-2" } }) }),
			),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_subject_mismatch",
				fields: { action: "oauth.authorize" },
			},
		]);
		await flush();
		expect(events).toEqual([
			{
				timestamp: NOW,
				type: "session.admission.subject_mismatch",
				subject: "user-1",
				details: { sid: "sid-1", claimedSubject: "user-2", action: "oauth.authorize" },
			},
		]);
	});

	it("compares a code claim's second read with the first read's subject", async () => {
		expect(
			await admitSession(
				deps(),
				request({ claim: codeClaim({ sid: "sid-1" }, { subject: "user-2" }) }),
			),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
		expect(
			await admitSession(
				deps(),
				request({ claim: codeClaim({ sid: "sid-1" }, { subject: "user-1" }) }),
			),
		).toMatchObject({ outcome: "admitted" });
	});

	it("logs and audits nothing when the subjects agree, and nothing without a logger or a sink", async () => {
		const { logger, lines } = recordingLogger();
		const { sink, events } = recordingSink();
		await admitSession(deps({ logger, auditSink: sink }), request());
		await flush();
		expect(lines).toEqual([]);
		expect(events).toEqual([]);
		// No logger, no sink: the refusal stands all the same.
		expect(
			await admitSession(deps(), request({ claim: cookie({ user: { id: "user-2" } }) })),
		).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
	});
});

describe("step 4 — the revocation boundary", () => {
	it("answers revoked for a session established at or before the subject's boundary, within the skew", async () => {
		const record = session({ authTime: minutesAgo(5) });
		for (const boundary of [
			minutesAgo(5),
			minutesAgo(1),
			new Date(minutesAgo(5).getTime() - 999),
		]) {
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						subjectRevocation: revocationOf(async () => boundary),
					}),
					request(),
				),
				boundary.toISOString(),
			).toEqual({ outcome: "revoked" });
		}
	});

	it("admits a session established after the boundary, or with no boundary in force", async () => {
		const record = session({ authTime: minutesAgo(5) });
		for (const boundary of [null, minutesAgo(6)]) {
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						subjectRevocation: revocationOf(async () => boundary),
					}),
					request(),
				),
				String(boundary),
			).toMatchObject({ outcome: "admitted" });
		}
	});

	it("reads the boundary for the record's subject", async () => {
		const asked: string[] = [];
		await admitSession(
			deps({
				subjectRevocation: revocationOf(async (subject) => {
					asked.push(subject);
					return null;
				}),
			}),
			request(),
		);
		expect(asked).toEqual(["user-1"]);
	});

	it("answers unavailable (revocation_boundary) for a throw, or an answer that is neither null nor a valid date, logged once", async () => {
		const { logger, lines } = recordingLogger();
		for (const answer of [
			async () => {
				throw new Error("down");
			},
			async () => "2026-01-01",
			async () => new Date(Number.NaN),
			async () => undefined,
			async () => 0,
		]) {
			lines.length = 0;
			expect(
				await admitSession(
					deps({ subjectRevocation: revocationOf(answer), logger }),
					request({ action: ADMISSION_ACTIONS["oauth.consent"] }),
				),
			).toEqual({ outcome: "unavailable", store: "revocation_boundary" });
			expect(lines).toHaveLength(1);
			expect(lines[0]).toMatchObject({
				level: "error",
				message: "session_admission_unavailable",
				fields: { store: "revocation_boundary", action: "oauth.consent" },
			});
		}
	});

	it("does not read the boundary for a token carrier: verifyJwt reads it, so the two readings do not double up", async () => {
		let asked = 0;
		expect(
			await admitSession(
				deps({
					subjectRevocation: revocationOf(async () => {
						asked++;
						return minutesAgo(1);
					}),
				}),
				request({ claim: tokenClaim({ sid: "sid-1", sub: "user-1" }) }),
			),
		).toMatchObject({ outcome: "admitted" });
		expect(asked).toBe(0);
	});

	it("does not read the boundary without a store: no record, no authTime and no sub to compare", async () => {
		let asked = 0;
		expect(
			await admitSession(
				deps({
					userSessionStore: undefined,
					subjectRevocation: revocationOf(async () => {
						asked++;
						return minutesAgo(1);
					}),
				}),
				request(),
			),
		).toMatchObject({ outcome: "admitted", session: null });
		expect(asked).toBe(0);
	});

	it("reads the boundary before any requirement is asked", async () => {
		let asked = 0;
		const watching = met("watch", {
			admit: async () => {
				asked++;
				return { outcome: "met" };
			},
		});
		await admitSession(
			deps({
				subjectRevocation: revocationOf(async () => minutesAgo(1)),
				requirements: resolverForTests([watching]),
			}),
			request(),
		);
		expect(asked).toBe(0);
	});
});

describe("step 5 — the requirements", () => {
	it("hands each requirement a view of the session — sid, sub, authTime, expiresAt — never the record, with the D9 reading, the action, the asks and now", async () => {
		const seen: RequirementInput[] = [];
		const record = session({ amr: ["hwk", "fed"], authentication: undefined });
		await admitSession(
			deps({
				userSessionStore: holding(record),
				requirements: resolverForTests([
					met("watch", {
						admit: async (input) => {
							seen.push(input);
							return { outcome: "met" };
						},
					}),
				]),
			}),
			request({ asks: { acrValues: ["urn:x"] } }),
		);
		expect(seen).toHaveLength(1);
		const input = seen[0] as RequirementInput;
		expect(input.session).toEqual({
			sid: "sid-1",
			sub: "user-1",
			authTime: record.authTime,
			expiresAt: record.expiresAt,
		});
		expect(input.session).not.toBe(record);
		expect(Object.keys(input.session ?? {})).toEqual(["sid", "sub", "authTime", "expiresAt"]);
		// The vouched amr, split as D9 reads a pre-upgrade record: `hwk` is an
		// untrusted IdP's word.
		expect(input.authentication).toEqual({
			authentication: {
				primary: "fed",
				federation: undefined,
				upstreamAmr: ["hwk"],
				mfaAt: undefined,
			},
			amr: ["fed"],
		});
		expect(input.carrier).toBe("cookie");
		expect(input.action).toEqual({ name: "oauth.authorize", grade: "use" });
		expect(input.asks).toEqual({ acrValues: ["urn:x"] });
		expect(input.now).toEqual(NOW);
	});

	it("builds a token carrier's authentication from the token's amr when no record was read: the primary from fed or pwd, else unknown, no mfaAt, the amr as vouched", async () => {
		const seen: RequirementInput[] = [];
		const watching = met("watch", {
			admit: async (input) => {
				seen.push(input);
				return { outcome: "met" };
			},
		});
		const without = deps({
			userSessionStore: undefined,
			requirements: resolverForTests([watching]),
		});
		for (const amr of [["pwd", "otp", "mfa"], ["hwk", "fed"], ["otp"], undefined]) {
			await admitSession(without, request({ claim: tokenClaim({ sub: "user-1", amr }) }));
		}
		expect(seen.map((input) => input.authentication)).toEqual([
			{
				authentication: {
					primary: "pwd",
					federation: undefined,
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
				amr: ["pwd", "otp", "mfa"],
			},
			{
				authentication: {
					primary: "fed",
					federation: undefined,
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
				amr: ["hwk", "fed"],
			},
			{ authentication: undefined, amr: ["otp"] },
			{ authentication: undefined, amr: [] },
		]);
		// With a record, the record's reading wins over the token's amr.
		await admitSession(
			deps({ requirements: resolverForTests([watching]) }),
			request({ claim: tokenClaim({ sid: "sid-1", sub: "user-1", amr: ["hwk", "fed"] }) }),
		);
		expect(seen.at(-1)?.authentication).toEqual({
			authentication: {
				primary: "pwd",
				federation: undefined,
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
			amr: ["pwd"],
		});
	});

	it("asks every requirement for use and credential_change, in registration order", async () => {
		const asked: string[] = [];
		const watching = (name: string) =>
			met(name, {
				admit: async () => {
					asked.push(name);
					return { outcome: "met" };
				},
			});
		const requirements = resolverForTests([watching("b"), watching("a")]);
		await admitSession(deps({ requirements }), request());
		await admitSession(
			deps({ requirements }),
			request({ action: ADMISSION_ACTIONS["session.link"] }),
		);
		expect(asked).toEqual(["b", "a", "b", "a"]);
	});

	it("asks no requirement for a remediation action a registered requirement declared: the route belongs to the requirement", async () => {
		let asked = 0;
		const owner = met("mfa", {
			remediations: ["mfa.step_up"],
			admit: async () => {
				asked++;
				return { outcome: "unmet" };
			},
		});
		expect(
			await admitSession(
				deps({ requirements: resolverForTests([owner, met("other")]) }),
				request({ action: ADMISSION_ACTIONS["mfa.step_up"] }),
			),
		).toMatchObject({ outcome: "admitted" });
		expect(asked).toBe(0);
	});

	it("treats a remediation no registered requirement declared as credential_change, and says so once per process per name", async () => {
		const { logger, lines } = recordingLogger();
		const seen: RequirementInput["action"][] = [];
		const watching = met("watch", {
			admit: async ({ action }) => {
				seen.push(action);
				return { outcome: "met" };
			},
		});
		const undeclared = { name: "deployment.mislabelled", grade: "remediation" } as const;
		const first = deps({ requirements: resolverForTests([watching]), logger });
		await admitSession(first, request({ action: undeclared }));
		await admitSession(first, request({ action: undeclared }));
		expect(seen).toEqual([
			{ name: "deployment.mislabelled", grade: "credential_change" },
			{ name: "deployment.mislabelled", grade: "credential_change" },
		]);
		expect(lines).toEqual([
			{
				level: "warn",
				message: "session_admission_remediation_undeclared",
				fields: { action: "deployment.mislabelled" },
			},
		]);
	});

	it("answers unavailable (the requirement's name) when a requirement throws, logged once: a requirement is never trusted to fail open", async () => {
		const { logger, lines } = recordingLogger();
		const failing = met("risk", {
			admit: async () => {
				throw new Error("scorer down");
			},
		});
		expect(
			await admitSession(
				deps({ requirements: resolverForTests([failing, met("after")]), logger }),
				request({ action: { name: "deployment.custom", grade: "use" } }),
			),
		).toEqual({ outcome: "unavailable", store: "risk" });
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "risk", action: "custom" },
		});
	});

	it("answers unavailable (the requirement's name) for a verdict that is not one of the four", async () => {
		const { logger, lines } = recordingLogger();
		for (const verdict of [
			undefined,
			"met",
			{ outcome: "maybe" },
			{ outcome: "step_up" },
			{ outcome: "step_up", whenStillUnmet: "retry" },
		]) {
			lines.length = 0;
			const odd = met("odd", { admit: async () => verdict as never });
			expect(
				await admitSession(deps({ requirements: resolverForTests([odd]), logger }), request()),
				JSON.stringify(verdict),
			).toEqual({ outcome: "unavailable", store: "odd" });
			expect(lines).toHaveLength(1);
		}
	});

	it("answers the requirement's registered page on step_up, never one the verdict names: a getter is read once at registration", async () => {
		let reads = 0;
		const record = session();
		const requirement = {
			name: "r",
			reach: new Set(["risk-ok"]),
			get stepUpPage() {
				reads++;
				return { url: "/r", params: { v: String(reads) } };
			},
			remediations: [],
			hintKeys: [],
			admit: async () =>
				({
					outcome: "step_up",
					whenStillUnmet: "unmet",
					page: { url: "/evil", params: {} },
				}) as never,
		} satisfies SessionRequirement;
		const requirements = resolverForTests([requirement]);
		expect(reads).toBe(1);
		expect(
			await admitSession(deps({ userSessionStore: holding(record), requirements }), request()),
		).toEqual({
			outcome: "step_up",
			requirement: "r",
			session: record,
			page: { url: "/r", params: { v: "1" } },
			acrValues: [],
			whenStillUnmet: "unmet",
		});
		expect(reads).toBe(1);
	});

	it("carries the live session on reauthenticate, step_up and unmet: /authorize decides freshness on it first", async () => {
		const record = session();
		for (const verdict of [
			{ outcome: "reauthenticate" as const },
			{ outcome: "unmet" as const },
			{ outcome: "step_up" as const, whenStillUnmet: "reauthenticate" as const },
		]) {
			const requirement = met("r", {
				reach: new Set(["risk-ok"]),
				stepUpPage: { url: "/r", params: {} },
				admit: async () => verdict,
			});
			expect(
				await admitSession(
					deps({
						userSessionStore: holding(record),
						requirements: resolverForTests([requirement]),
					}),
					request(),
				),
				verdict.outcome,
			).toMatchObject({ outcome: verdict.outcome, requirement: "r", session: record });
		}
	});
});

describe("step 6 — acr_values, with the reach of what is registered", () => {
	const table = readAcrTable({ "urn:o3co:acr:mfa": ["mfa"], "urn:example:pwd": ["pwd"] });

	it("selects over the vouched amr, with reach the union of every requirement's reach when the session is live", async () => {
		const requirements = resolverForTests([
			met("a", { reach: new Set(["risk-ok"]), stepUpPage: { url: "/a", params: {} } }),
			met("b", { reach: new Set(["mfa"]), stepUpPage: { url: "/b", params: {} } }),
		]);
		expect(
			await admitSession(
				deps({ acrTable: table, requirements }),
				request({ asks: { acrValues: ["urn:o3co:acr:mfa"] } }),
			),
		).toMatchObject({ outcome: "step_up", requirement: "b", acrValues: ["urn:o3co:acr:mfa"] });
		expect(
			await admitSession(
				deps({ acrTable: table, requirements }),
				request({ asks: { acrValues: ["urn:example:pwd"] } }),
			),
		).toMatchObject({ outcome: "admitted", acr: "urn:example:pwd" });
	});

	it("reaches nothing without a session: nothing can be stepped up onto no session", async () => {
		const requirements = resolverForTests([
			met("b", { reach: new Set(["mfa"]), stepUpPage: { url: "/b", params: {} } }),
		]);
		expect(
			await admitSession(
				deps({ acrTable: table, requirements, userSessionStore: undefined }),
				request({ asks: { acrValues: ["urn:o3co:acr:mfa"] } }),
			),
		).toEqual({ outcome: "unmet", requirement: "acr", session: null });
	});

	it("asks nothing of the table when no acr is asked for, and answers no acr", async () => {
		for (const asks of [undefined, {}, { acrValues: [] }]) {
			expect(
				await admitSession(deps({ acrTable: table }), request({ asks })),
				JSON.stringify(asks),
			).toEqual({ outcome: "admitted", session: session(), acr: undefined });
		}
	});
});

describe("the actions (D4)", () => {
	it("names the bundled actions with their grades, each frozen", () => {
		expect(
			Object.fromEntries(
				Object.entries(ADMISSION_ACTIONS).map(([key, action]) => [key, action.grade]),
			),
		).toEqual({
			"oauth.authorize": "use",
			"oauth.consent": "use",
			"oauth.session_grant": "use",
			"oauth.code_exchange": "use",
			"device.lookup": "use",
			"device.approve": "use",
			"device.deny": "use",
			"federation_grants.connect": "use",
			"federation_grants.consent": "use",
			"federation_grants.callback": "use",
			"session.link": "credential_change",
			"session.link_callback": "use",
			"webauthn.register": "credential_change",
			"mfa.manage": "credential_change",
			"mfa.step_up": "remediation",
		});
		expect(Object.isFrozen(ADMISSION_ACTIONS)).toBe(true);
		for (const [key, action] of Object.entries(ADMISSION_ACTIONS)) {
			expect(action.name, key).toBe(key);
			expect(Object.isFrozen(action), key).toBe(true);
		}
	});

	it("logs a bundled action by its name and any other as custom", async () => {
		const { logger, lines } = recordingLogger();
		const down = storeOf(async () => {
			throw new Error("down");
		});
		await admitSession(
			deps({ userSessionStore: down, logger }),
			request({ action: ADMISSION_ACTIONS["device.approve"] }),
		);
		await admitSession(
			deps({ userSessionStore: down, logger }),
			request({ action: { name: "deployment.export", grade: "use" } }),
		);
		expect(lines.map((line) => line.fields.action)).toEqual(["device.approve", "custom"]);
	});
});

describe("the clock", () => {
	it("defaults to the wall clock: a record that expires in the future is live", async () => {
		const record = session({ expiresAt: new Date(Date.now() + 60_000) });
		const { now: _seam, ...withoutClock } = deps({ userSessionStore: holding(record) });
		expect(await admitSession(withoutClock, request())).toMatchObject({ outcome: "admitted" });
	});
});
