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
 * `admitSession`'s last step: once a requirement was asked about a live
 * record, the record and the revocation boundary are read again, and that
 * reading decides whether the answer stands. Each pending requirement here
 * is a promise the test settles after changing what the stores hold.
 */

import { describe, expect, it } from "vitest";
import type { AuditEvent, AuditSink } from "#/audit/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitSession,
	type CodeCarrier,
	codeClaimFirstRead,
	cookieClaim,
	tokenClaim,
	viewOf,
} from "#/session-admission/admit.mjs";
import type {
	AdmissionDeps,
	IssuedRemediationAction,
	RequirementInput,
	RequirementVerdict,
	SessionClaim,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import { issuedRemediationActions } from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import { newRenewalNonce } from "#/user-sessions/renewalNonce.mjs";
import type { SubjectRevocation, UserSession, UserSessionStore } from "#/user-sessions/types.mjs";
import { TEST_ACTIONS } from "./actions.fixture.mjs";

/** A code record as `/authorize` mints it over a password session: its `sid`, and how the session had authenticated. */
const passwordCode = (sid: string): CodeCarrier => {
	const code: { readonly sid: string; readonly authentication: unknown } = {
		sid,
		authentication: { primary: "pwd", mfaAt: undefined },
	};
	return code;
};

const NOW = new Date("2026-09-28T12:00:00Z");
const ISSUER = "https://auth.test";

const session = (over: Partial<UserSession> = {}): UserSession => ({
	sid: "sid-1",
	sub: "user-1",
	authTime: new Date(NOW.getTime() - 5 * 60_000),
	createdAt: new Date(NOW.getTime() - 5 * 60_000),
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

/**
 * What the stores hold, which a test changes while a requirement is pending:
 * the record under `sid-1`, the sessions boundary, and the clock. Each read
 * is counted, and either read may be made to throw from its nth call.
 */
interface World {
	record: UserSession | null;
	boundary: Date | null;
	now: Date;
	gets: number;
	boundaryReads: number;
	getThrowsFrom?: number;
	boundaryThrowsFrom?: number;
	readonly store: UserSessionStore;
	readonly revocation: SubjectRevocation;
}

const world = (record: UserSession | null = session()): World => {
	const w: World = {
		record,
		boundary: null,
		now: NOW,
		gets: 0,
		boundaryReads: 0,
		store: {
			kind: "test",
			create: async () => {},
			get: async (sid: string) => {
				w.gets++;
				if (w.getThrowsFrom !== undefined && w.gets >= w.getThrowsFrom) {
					throw new Error("store down");
				}
				return w.record !== null && sid === w.record.sid ? w.record : null;
			},
			delete: async () => {},
		},
		revocation: {
			kind: "test",
			revokeBefore: async () => {},
			revokedBefore: async () => {
				w.boundaryReads++;
				if (w.boundaryThrowsFrom !== undefined && w.boundaryReads >= w.boundaryThrowsFrom) {
					throw new Error("boundary down");
				}
				return w.boundary;
			},
		},
	};
	return w;
};

/** A requirement whose `admit` waits until the test settles it, with the inputs it was handed. */
interface Pending {
	readonly requirement: SessionRequirement;
	/** Resolves once `admit` has been called. */
	readonly asked: Promise<RequirementInput>;
	readonly answer: (verdict: RequirementVerdict) => void;
	readonly fail: (err: unknown) => void;
}

const pending = (name = "slow", over: Partial<SessionRequirement> = {}): Pending => {
	let onAsked: (input: RequirementInput) => void = () => {};
	let settle: (verdict: RequirementVerdict) => void = () => {};
	let reject: (err: unknown) => void = () => {};
	const asked = new Promise<RequirementInput>((resolve) => {
		onAsked = resolve;
	});
	return {
		requirement: {
			name,
			reach: new Set(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: (input) =>
				new Promise<RequirementVerdict>((resolve, rejectWith) => {
					settle = resolve;
					reject = rejectWith;
					onAsked(input);
				}),
			...over,
		},
		asked,
		answer: (verdict) => settle(verdict),
		fail: (err) => reject(err),
	};
};

const met = (name: string, over: Partial<SessionRequirement> = {}): SessionRequirement => ({
	name,
	reach: new Set(),
	stepUpPage: undefined,
	remediations: [],
	hintKeys: [],
	admit: async () => ({ outcome: "met" }),
	...over,
});

interface Line {
	readonly level: string;
	readonly fields: Record<string, unknown>;
	readonly message: string | undefined;
}

const recordingLogger = (): { readonly logger: Logger; readonly lines: Line[] } => {
	const lines: Line[] = [];
	const at =
		(level: string) =>
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
			kind: "test",
			record: async (event) => {
				events.push(event);
			},
		},
		events,
	};
};

const depsOver = (
	w: World,
	requirements: readonly SessionRequirement[],
	over: Partial<AdmissionDeps> = {},
): AdmissionDeps => ({
	userSessionStore: w.store,
	subjectRevocation: w.revocation,
	requirements: resolverForTests([...requirements], {
		allowAnyReach: true,
		issuer: ISSUER,
		actions: TEST_ACTIONS,
	}),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
	now: () => w.now,
	...over,
});

const cookie = (over: Record<string, unknown> = {}): SessionClaim =>
	cookieClaim({
		session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" }, ...over },
	});

const flush = () => new Promise((resolve) => setImmediate(resolve));

describe("admission reads the record and the boundary again after its requirements answer", () => {
	it("answers revoked when the boundary is stamped while a requirement is pending", async () => {
		const w = world();
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.boundary = NOW;
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "revoked" });
	});

	it("answers not_live (gone) when the record is deleted while a requirement is pending", async () => {
		const w = world();
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.record = null;
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "not_live", reason: "gone" });
	});

	it("answers not_live (renewed) when the record moves to another renewal nonce while a requirement is pending", async () => {
		const held = newRenewalNonce();
		const w = world(session({ renewalNonce: held }));
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie({ renewalNonce: held }),
			action: "test.use",
		});
		await slow.asked;
		w.record = session({ renewalNonce: newRenewalNonce() });
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "not_live", reason: "renewed" });
	});

	for (const [carrier, claim] of [
		["a cookie", cookie()],
		["a code's first read, which names no subject", codeClaimFirstRead(passwordCode("sid-1"))],
	] as const) {
		it(`answers not_live (subject_mismatch) for ${carrier} when the record under the sid names another subject by then, logged and audited once`, async () => {
			const w = world();
			const { logger, lines } = recordingLogger();
			const { sink, events } = recordingSink();
			const slow = pending();
			const admission = admitSession(depsOver(w, [slow.requirement], { logger, auditSink: sink }), {
				claim,
				action: "test.use",
			});
			await slow.asked;
			w.record = session({ sub: "user-2" });
			slow.answer({ outcome: "met" });
			expect(await admission).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
			await flush();
			expect(lines.filter((l) => l.message === "session_admission_subject_mismatch")).toHaveLength(
				1,
			);
			expect(events).toHaveLength(1);
			expect(events[0]).toMatchObject({
				type: "session.admission.subject_mismatch",
				subject: "user-2",
				details: { sid: "sid-1", claimedSubject: "user-1", recordSubject: "user-2" },
			});
		});
	}

	it("answers not_live (gone) when the record expires, on a fresh clock reading, while a requirement is pending", async () => {
		const w = world();
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		const input = await slow.asked;
		w.now = new Date(NOW.getTime() + 2 * 3_600_000);
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "not_live", reason: "gone" });
		// The requirement was handed the first reading's instant.
		expect(input.now).toEqual(NOW);
	});

	it("answers revoked over a requirement's step_up when the boundary is stamped meanwhile: the session's state takes precedence over the verdict", async () => {
		const w = world();
		const slow = pending("slow", { stepUpPage: { url: "/step-up", params: {} } });
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.boundary = NOW;
		slow.answer({ outcome: "step_up", whenStillUnmet: "unmet" });
		expect(await admission).toEqual({ outcome: "revoked" });
	});

	it("answers not_live over a requirement's unmet when the record is deleted meanwhile", async () => {
		const w = world();
		let laterAsked = false;
		const slow = pending();
		const later = met("later", {
			admit: async () => {
				laterAsked = true;
				return { outcome: "met" };
			},
		});
		const admission = admitSession(depsOver(w, [slow.requirement, later]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.record = null;
		slow.answer({ outcome: "unmet" });
		expect(await admission).toEqual({ outcome: "not_live", reason: "gone" });
		expect(laterAsked).toBe(false);
	});

	it("keeps the first reading's session and view in the answer: the second reading only decides whether it stands", async () => {
		const first = session();
		const w = world(first);
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.record = session({ expiresAt: new Date(NOW.getTime() + 7_200_000) });
		slow.answer({ outcome: "met" });
		const answer = await admission;
		expect(answer).toMatchObject({ outcome: "admitted", session: first });
		expect(answer).toMatchObject({ view: viewOf(first, false) });
	});

	it("reads a token carrier's record again but never its boundary, which verifyJwt reads", async () => {
		const w = world();
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: tokenClaim({ sub: "user-1", sid: "sid-1", amr: ["pwd"] }),
			action: "test.use",
		});
		await slow.asked;
		w.record = null;
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "not_live", reason: "gone" });
		expect(w.gets).toBe(2);
		expect(w.boundaryReads).toBe(0);
	});

	it("reads again after the last requirement asked, when an earlier one answered met", async () => {
		const w = world();
		const slow = pending("second");
		const admission = admitSession(depsOver(w, [met("first"), slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.boundary = NOW;
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "revoked" });
		expect([w.gets, w.boundaryReads]).toEqual([2, 2]);
	});

	it("rejects, as at the check, when the clock throws on the last reading", async () => {
		const w = world();
		let readings = 0;
		const clock = () => {
			readings++;
			if (readings > 1) throw new Error("clock down");
			return NOW;
		};
		await expect(
			admitSession(depsOver(w, [met("a")], { now: clock }), {
				claim: cookie(),
				action: "test.use",
			}),
		).rejects.toThrow("clock down");
		expect(w.gets).toBe(1);
	});
});

describe("an outage on the second reading is admission's unavailable, as on the first", () => {
	it("answers unavailable (user_session) when only the second record read throws, logged once at error", async () => {
		const w = world();
		w.getThrowsFrom = 2;
		const { logger, lines } = recordingLogger();
		expect(
			await admitSession(depsOver(w, [met("ok")], { logger }), {
				claim: cookie(),
				action: "test.use",
			}),
		).toEqual({ outcome: "unavailable", store: "user_session" });
		expect(lines).toEqual([
			expect.objectContaining({
				level: "error",
				message: "session_admission_unavailable",
				fields: expect.objectContaining({ store: "user_session", action: "test.use" }),
			}),
		]);
	});

	it("answers unavailable (revocation_boundary) when only the second boundary read throws, logged once at error", async () => {
		const w = world();
		w.boundaryThrowsFrom = 2;
		const { logger, lines } = recordingLogger();
		expect(
			await admitSession(depsOver(w, [met("ok")], { logger }), {
				claim: cookie(),
				action: "test.use",
			}),
		).toEqual({ outcome: "unavailable", store: "revocation_boundary" });
		expect(lines).toEqual([
			expect.objectContaining({
				level: "error",
				message: "session_admission_unavailable",
				fields: expect.objectContaining({ store: "revocation_boundary", action: "test.use" }),
			}),
		]);
	});

	it("answers unavailable (the requirement's name) at once when a requirement throws, with no second reading", async () => {
		const w = world();
		const { logger, lines } = recordingLogger();
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement], { logger }), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		slow.fail(new Error("risk engine down"));
		expect(await admission).toEqual({ outcome: "unavailable", store: "slow" });
		expect(w.gets).toBe(1);
		expect(w.boundaryReads).toBe(1);
		expect(lines).toHaveLength(1);
	});

	it("answers unavailable (the requirement's name) at once for an answer that is not a verdict, with no second reading, whatever the stores hold by then", async () => {
		const w = world();
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.record = null;
		slow.answer({ outcome: "garbage" } as never);
		expect(await admission).toEqual({ outcome: "unavailable", store: "slow" });
		expect([w.gets, w.boundaryReads]).toEqual([1, 1]);
	});

	it("answers unavailable (revocation_boundary) when the second boundary read answers neither a date nor null", async () => {
		const w = world();
		const slow = pending();
		const admission = admitSession(depsOver(w, [slow.requirement]), {
			claim: cookie(),
			action: "test.use",
		});
		await slow.asked;
		w.boundary = new Date(Number.NaN);
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "unavailable", store: "revocation_boundary" });
	});

	it("keeps the subject mismatch on the last reading when the audit sink cannot be read", async () => {
		const w = world();
		const slow = pending();
		const base = depsOver(w, [slow.requirement]);
		const admission = admitSession(
			{
				...base,
				get auditSink(): AuditSink {
					throw new Error("sink down");
				},
			},
			{ claim: cookie(), action: "test.use" },
		);
		await slow.asked;
		w.record = session({ sub: "user-2" });
		slow.answer({ outcome: "met" });
		expect(await admission).toEqual({ outcome: "not_live", reason: "subject_mismatch" });
	});
});

describe("how many reads admission makes", () => {
	it("reads the record and the boundary once each when no requirement is registered", async () => {
		const w = world();
		expect(
			await admitSession(depsOver(w, []), { claim: cookie(), action: "test.use" }),
		).toMatchObject({ outcome: "admitted" });
		expect([w.gets, w.boundaryReads]).toEqual([1, 1]);
	});

	it("reads each once for the remediation core issued, which asks no requirement", async () => {
		const w = world();
		const owner = met("mfa", { remediations: ["mfa.step_up"] });
		const deps = depsOver(w, [owner]);
		const issued = issuedRemediationActions(owner)?.step_up as IssuedRemediationAction;
		expect(await admitSession(deps, { claim: cookie(), action: issued })).toMatchObject({
			outcome: "admitted",
		});
		expect([w.gets, w.boundaryReads]).toEqual([1, 1]);
	});

	it("reads each twice when a requirement is asked, off deps once each", async () => {
		const w = world();
		let storeReads = 0;
		let revocationReads = 0;
		let clockReads = 0;
		const base = depsOver(w, [met("a"), met("b")]);
		const counting = {
			...base,
			get userSessionStore() {
				storeReads++;
				return w.store;
			},
			get subjectRevocation() {
				revocationReads++;
				return w.revocation;
			},
			get now() {
				clockReads++;
				return () => w.now;
			},
		};
		expect(await admitSession(counting, { claim: cookie(), action: "test.use" })).toMatchObject({
			outcome: "admitted",
		});
		expect([w.gets, w.boundaryReads]).toEqual([2, 2]);
		expect([storeReads, revocationReads, clockReads]).toEqual([1, 1, 1]);
	});

	it("reads nothing without a store, with or without requirements, and answers as before", async () => {
		const w = world();
		for (const requirements of [[], [met("a")]]) {
			expect(
				await admitSession(depsOver(w, requirements, { userSessionStore: undefined }), {
					claim: cookie(),
					action: "test.use",
				}),
			).toMatchObject({ outcome: "admitted", session: null });
		}
		expect([w.gets, w.boundaryReads]).toEqual([0, 0]);
	});

	it("answers no_sid for a cookie without a sid, never asking a requirement", async () => {
		const w = world();
		let asked = false;
		const watching = met("watch", {
			admit: async () => {
				asked = true;
				return { outcome: "met" };
			},
		});
		expect(
			await admitSession(depsOver(w, [watching]), {
				claim: cookie({ sid: undefined }),
				action: "test.use",
			}),
		).toEqual({ outcome: "not_live", reason: "no_sid" });
		expect(asked).toBe(false);
		expect([w.gets, w.boundaryReads]).toEqual([0, 0]);
	});

	it("reads nothing for a token carrier without a sid, its requirements asked on the token's own amr", async () => {
		const w = world();
		let asked = false;
		const watching = met("watch", {
			admit: async () => {
				asked = true;
				return { outcome: "met" };
			},
		});
		expect(
			await admitSession(depsOver(w, [watching]), {
				claim: tokenClaim({ sub: "user-1", amr: ["pwd"] }),
				action: "test.use",
			}),
		).toMatchObject({ outcome: "admitted", session: null });
		expect(asked).toBe(true);
		expect([w.gets, w.boundaryReads]).toEqual([0, 0]);
	});

	it("reads a token carrier's record twice and its boundary never when a requirement is asked", async () => {
		const w = world();
		expect(
			await admitSession(depsOver(w, [met("a")]), {
				claim: tokenClaim({ sub: "user-1", sid: "sid-1", amr: ["pwd"] }),
				action: "test.use",
			}),
		).toMatchObject({ outcome: "admitted" });
		expect([w.gets, w.boundaryReads]).toEqual([2, 0]);
	});
});
