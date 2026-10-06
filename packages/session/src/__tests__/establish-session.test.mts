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
 * `establishSession` — the tail of a login both routes share, and the MFA
 * package's completion after them: what it writes, from the `Establishment`
 * core built and nothing beside it (ADR 2026-09-28-session-admission, D5), its
 * sequence, what it hands each write, and the rollback ladder at every point
 * it can fail, driven by stores and steps that fail where a test says.
 */

import {
	type AdmissionDeps,
	admitPrimary,
	type Establishment,
	establishWithoutAsking,
	passwordPrimary,
	passwordSessionAuthentication,
	resumePrimary,
	type SessionCloseCause,
	type SessionCloseOutcome,
	type SessionLifecycle,
	type SessionOpenOutcome,
	type SessionRequirement,
	type SubjectSessionIndex,
	type User,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import type { Request } from "express";
import { describe, expect, it, vi } from "vitest";
import {
	type EstablishSessionReporter,
	type EstablishSessionStep,
	establishSession,
} from "#/establish-session.mjs";

const TTL_MS = 3_600_000;
const user: User = { id: "u-1", username: "alice", email: "alice@example.com" };
const authTime = new Date("2026-09-28T09:00:00.000Z");
const claims = { email: "alice@example.com" };

/** What admission is handed: the resolver over `requirements`, nothing else read. */
const admissionDeps = (requirements: readonly SessionRequirement[] = []): AdmissionDeps => ({
	userSessionStore: undefined,
	subjectRevocation: undefined,
	requirements: resolverForTests(requirements, { issuer: "https://auth.test" }),
	acrTable: {},
	logger: undefined,
	auditSink: undefined,
});

/** The password login of `user`, as admission establishes it with no requirement registered. */
async function passwordEstablishment(redirectTo?: string): Promise<Establishment> {
	const admission = await admitPrimary(
		admissionDeps(),
		passwordPrimary({ subject: user.id, user, claims, authTime, redirectTo, request: {} }),
	);
	if (admission.outcome !== "establish") throw new Error(`admission answered ${admission.outcome}`);
	return admission.establishment;
}

type Failures = {
	readonly create?: Error;
	readonly addSid?: Error;
	readonly delete?: Error;
	readonly removeSid?: Error;
	readonly regenerate?: Error;
	readonly save?: Error;
	/** Thrown synchronously by `regenerate`, before its callback — never handed to it. */
	readonly regenerateThrows?: Error;
	/** Thrown synchronously by `save`, as a store serialising the record does. */
	readonly saveThrows?: Error;
	readonly before?: Error;
	readonly beforeUndo?: Error;
	readonly after?: Error;
	readonly afterUndo?: Error;
	/** The lifecycle's `close` rejects with it, or answers `unavailable`. */
	readonly close?: Error | "unavailable";
};

type FakeSession = Record<string, unknown> & {
	regenerate(cb: (err: unknown) => void): void;
	save(cb: (err: unknown) => void): void;
};

/**
 * Every collaborator a login's tail touches, each writing its name to `trace`
 * as it runs and failing where `fail` says — so a test reads the whole
 * sequence, and the whole rollback, off one list.
 */
function harness(
	fail: Failures = {},
	shape: {
		readonly userSessionStore?: boolean;
		readonly subjectSessionIndex?: boolean;
		readonly steps?: boolean;
		readonly redirectTo?: string;
		/** The reporter's calls join the trace where they happen. */
		readonly traceReporter?: boolean;
		/**
		 * A session lifecycle whose `open` answers this (`opened` when absent), or
		 * rejects with it; `false`: none is wired.
		 */
		readonly lifecycle?: SessionOpenOutcome["outcome"] | Error | false;
	} = {},
) {
	const trace: string[] = [];
	const step = (name: string, error: Error | undefined) =>
		vi.fn(async () => {
			trace.push(name);
			if (error) throw error;
		});

	const userSessionStore = {
		kind: "memory",
		create: step("create", fail.create),
		get: vi.fn(async () => null),
		delete: step("delete", fail.delete),
	} as unknown as UserSessionStore & { create: ReturnType<typeof vi.fn> };
	const subjectSessionIndex = {
		kind: "memory",
		addSid: step("addSid", fail.addSid),
		listSids: vi.fn(async () => []),
		removeSid: step("removeSid", fail.removeSid),
		removeBySubject: vi.fn(async () => {}),
	} as unknown as SubjectSessionIndex & { addSid: ReturnType<typeof vi.fn> };

	const before: EstablishSessionStep<"session_federation_index", "add" | "remove_by_sid"> = {
		store: "session_federation_index",
		step: "add",
		run: step("before", fail.before),
		undo: { step: "remove_by_sid", run: step("before-undo", fail.beforeUndo) },
	};
	const after: EstablishSessionStep<"federation_token", "attach" | "delete"> = {
		store: "federation_token",
		step: "attach",
		run: step("after", fail.after),
		undo: { step: "delete", run: step("after-undo", fail.afterUndo) },
	};

	const sessionLifecycle = {
		open: vi.fn(async (_sid: string, _request: { sub: string; expiresAt: Date }) => {
			trace.push("open");
			if (shape.lifecycle instanceof Error) throw shape.lifecycle;
			return { outcome: shape.lifecycle || "opened" } as SessionOpenOutcome;
		}),
		close: vi.fn(async (_sid: string, _cause: SessionCloseCause): Promise<SessionCloseOutcome> => {
			trace.push("close");
			if (fail.close instanceof Error) throw fail.close;
			if (fail.close === "unavailable") return { outcome: "unavailable" };
			return { outcome: "done", rps: [], federations: [] };
		}),
	} satisfies Pick<SessionLifecycle, "open" | "close">;

	// The express session: `regenerate` swaps in a fresh bag, as express-session
	// does, so a test can tell the flags landed on the new one and not the old.
	const req: { session: FakeSession | undefined } = { session: undefined };
	const save = vi.fn((cb: (err: unknown) => void) => {
		trace.push("save");
		if (fail.saveThrows) throw fail.saveThrows;
		cb(fail.save ?? null);
	});
	const regenerate = vi.fn((cb: (err: unknown) => void) => {
		trace.push("regenerate");
		if (fail.regenerateThrows) throw fail.regenerateThrows;
		if (fail.regenerate) {
			cb(fail.regenerate);
			return;
		}
		req.session = { id: "fresh", regenerate, save };
		cb(null);
	});
	req.session = { id: "stale", regenerate, save };

	// With `traceReporter`, what the reporter is told joins the trace at the
	// point it was told, so a test reads the outage's place among the rollback
	// steps — before any of them — and each rollback failure as it happens.
	const report = (name: string) =>
		vi.fn((..._args: unknown[]) => {
			if (shape.traceReporter) trace.push(name);
		});
	const reporter = {
		storeUnavailable: report("outage"),
		cleanupFailed: report("cleanup-failed"),
		subjectIndexWriteFailed: report("index-write-failed"),
	} satisfies EstablishSessionReporter<
		"session_federation_index" | "federation_token",
		"add" | "remove_by_sid" | "attach" | "delete"
	>;
	const reporterFactory = vi.fn((_record: { sid: string | undefined; sub: string }) => {
		trace.push("reporter");
		return reporter;
	});

	/** Establishes `establishment`, as the harness's stores and steps write it. */
	const establish = (establishment: Establishment) =>
		establishSession(establishment, {
			req: req as unknown as Request,
			...(shape.userSessionStore === false ? {} : { userSessionStore }),
			...(shape.subjectSessionIndex === false ? {} : { subjectSessionIndex }),
			...(shape.lifecycle === false ? {} : { sessionLifecycle }),
			sessionTtlMs: TTL_MS,
			...(shape.steps === false ? {} : { beforeRegenerate: [before], afterRegenerate: [after] }),
			reporter: reporterFactory,
		});
	/** Establishes the password login of `user`, with the shape's `redirectTo`. */
	const run = async () => establish(await passwordEstablishment(shape.redirectTo));

	return {
		run,
		establish,
		trace,
		req,
		userSessionStore,
		subjectSessionIndex,
		sessionLifecycle,
		before,
		after,
		reporter,
		reporterFactory,
	};
}

/** The `sid` the harness's store was handed. */
const createdSid = (h: ReturnType<typeof harness>): string =>
	(h.userSessionStore.create.mock.calls[0][0] as { sid: string }).sid;

describe("establishSession", () => {
	describe("what it writes: the establishment's primary, and nothing beside it", () => {
		it("writes the record and the session from the primary — its subject, user, claims, authTime, recorded, enrollment facts and redirectTo — whatever the caller hands beside it", async () => {
			const h = harness();
			const fedAuthTime = new Date("2026-09-28T08:00:00.000Z");
			const establishment = establishWithoutAsking({
				subject: "u-9",
				user: { id: "u-9", username: "fed-user" },
				claims: { email: "fed-user@example.com", federated: { idp: { sub: "ext-1" } } },
				federation: "idp",
				upstreamAmr: ["otp"],
				trusted: true,
				authTime: fedAuthTime,
				redirectTo: "https://app.example.com/federated",
				request: {},
			});
			// What a caller might try to hand in beside it: nothing reads it.
			const beside = {
				user: { id: "someone-else" },
				claims: { email: "forged@example.com" },
				recorded: {
					amr: ["pwd", "otp", "mfa"],
					authentication: { primary: "pwd", mfaAt: new Date() },
				},
				authTime: new Date(0),
				redirectTo: "https://evil.example.com/",
				enrollmentFacts: { witness: "enrolled", mailAddress: "address" },
			};

			const result = await establishSession(establishment, {
				...beside,
				req: h.req as unknown as Request,
				userSessionStore: h.userSessionStore,
				subjectSessionIndex: h.subjectSessionIndex,
				sessionLifecycle: h.sessionLifecycle,
				sessionTtlMs: TTL_MS,
				reporter: h.reporterFactory,
			} as never);

			const sid = createdSid(h);
			const expiresAt = new Date(fedAuthTime.getTime() + TTL_MS);
			expect(result).toEqual({ outcome: "established", sid });
			expect(h.userSessionStore.create).toHaveBeenCalledWith({
				sid,
				sub: "u-9",
				authTime: fedAuthTime,
				expiresAt,
				claims: { email: "fed-user@example.com", federated: { idp: { sub: "ext-1" } } },
				amr: ["otp", "fed"],
				authentication: {
					primary: "fed",
					federation: "idp",
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
				enrollmentFacts: { witness: "not_enrolled", mailAddress: "none" },
			});
			expect(h.subjectSessionIndex.addSid).toHaveBeenCalledWith("u-9", sid, expiresAt);
			expect(h.reporterFactory).toHaveBeenCalledWith({ sid, sub: "u-9" });
			expect(h.req.session).toMatchObject({
				id: "fresh",
				isAuthenticated: true,
				user: { id: "u-9", username: "fed-user" },
				sid,
				redirectTo: "https://app.example.com/federated",
			});
		});

		it("writes a resumed establishment's composed recorded: the second factor's values and when it was verified", async () => {
			const h = harness({}, { steps: false });
			const mfaAt = new Date("2026-09-28T09:01:00.000Z");
			const mfa: SessionRequirement = {
				name: "mfa",
				secondFactorAuthority: true,
				reach: new Set(["otp", "mfa"]),
				stepUpPage: { url: "/mfa", params: {} },
				remediations: ["mfa.step_up"],
				hintKeys: [],
				admit: async () => ({ outcome: "met" }),
				admitPrimary: async (primary) =>
					primary.recorded.authentication.mfaAt === undefined
						? { open: async () => ({ status: 403, body: { error: "mfa_required" } }) }
						: "establish",
			};
			const deps = admissionDeps([mfa]);
			const interrupted = await admitPrimary(
				deps,
				passwordPrimary({
					subject: user.id,
					user,
					claims,
					authTime,
					redirectTo: undefined,
					request: {},
				}),
			);
			if (interrupted.outcome !== "interrupt") throw new Error("expected an interruption");
			const resumed = await resumePrimary(deps, interrupted.continuation, {
				requirement: "mfa",
				adds: { amr: ["otp", "mfa"], mfaAt },
			});
			if (resumed.outcome !== "establish") throw new Error("expected an establishment");

			await h.establish(resumed.establishment);

			expect(h.userSessionStore.create).toHaveBeenCalledWith(
				expect.objectContaining({
					sub: "u-1",
					authTime,
					amr: ["pwd", "otp", "mfa"],
					authentication: {
						primary: "pwd",
						federation: undefined,
						upstreamAmr: undefined,
						mfaAt,
					},
				}),
			);
		});

		it("writes the enrollment facts the primary carries, read from its user: a password login's, and a resumed one's", async () => {
			const enrolled: User = { ...user, mfaEnrolled: true };
			const direct = harness({}, { steps: false });
			const admitted = await admitPrimary(
				admissionDeps(),
				passwordPrimary({
					subject: user.id,
					user: enrolled,
					claims,
					authTime,
					redirectTo: undefined,
					request: {},
				}),
			);
			if (admitted.outcome !== "establish") throw new Error("expected an establishment");
			await direct.establish(admitted.establishment);
			expect(direct.userSessionStore.create).toHaveBeenCalledWith(
				expect.objectContaining({
					enrollmentFacts: { witness: "enrolled", mailAddress: "address" },
				}),
			);

			const mfa: SessionRequirement = {
				name: "mfa",
				secondFactorAuthority: true,
				reach: new Set(["otp", "mfa"]),
				stepUpPage: { url: "/mfa", params: {} },
				remediations: ["mfa.step_up"],
				hintKeys: [],
				admit: async () => ({ outcome: "met" }),
				admitPrimary: async (primary) =>
					primary.recorded.authentication.mfaAt === undefined
						? { open: async () => ({ status: 403, body: { error: "mfa_required" } }) }
						: "establish",
			};
			const deps = admissionDeps([mfa]);
			const interrupted = await admitPrimary(
				deps,
				passwordPrimary({
					subject: user.id,
					user: { ...enrolled, email: "not an address" },
					claims,
					authTime,
					redirectTo: undefined,
					request: {},
				}),
			);
			if (interrupted.outcome !== "interrupt") throw new Error("expected an interruption");
			const resumed = await resumePrimary(deps, interrupted.continuation, {
				requirement: "mfa",
				adds: { amr: ["otp", "mfa"], mfaAt: new Date("2026-09-28T09:01:00.000Z") },
			});
			if (resumed.outcome !== "establish") throw new Error("expected an establishment");
			const after = harness({}, { steps: false });
			await after.establish(resumed.establishment);
			expect(after.userSessionStore.create).toHaveBeenCalledWith(
				expect.objectContaining({
					enrollmentFacts: { witness: "enrolled", mailAddress: "unreadable" },
				}),
			);
		});

		it("refuses what is not an Establishment core built — an object shaped like one, a copy of one — with a RangeError, before anything is written", async () => {
			const genuine = await passwordEstablishment();
			for (const forged of [
				{ primary: genuine.primary },
				{ ...genuine },
				Object.freeze({ primary: genuine.primary }),
				undefined,
			]) {
				const h = harness();
				await expect(h.establish(forged as unknown as Establishment)).rejects.toThrow(RangeError);
				expect(h.trace).toEqual([]);
				expect(h.userSessionStore.create).not.toHaveBeenCalled();
				expect(h.req.session).toMatchObject({ id: "stale" });
				expect(h.req.session).not.toHaveProperty("isAuthenticated");
			}
		});
	});

	describe("the sequence", () => {
		it("creates the record, indexes it, runs the caller's step, regenerates, runs the other step, writes the flags and saves — in that order", async () => {
			const h = harness();

			const result = await h.run();

			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"after",
				"save",
			]);
			expect(result).toEqual({ outcome: "established", sid: createdSid(h) });
			expect(h.reporter.storeUnavailable).not.toHaveBeenCalled();
			expect(h.reporter.cleanupFailed).not.toHaveBeenCalled();
			expect(h.reporter.subjectIndexWriteFailed).not.toHaveBeenCalled();
		});

		it("hands the record to the store as the input describes it, and the same sid and expiry to the index and the caller's steps", async () => {
			const h = harness();

			await h.run();

			const sid = createdSid(h);
			const expiresAt = new Date(authTime.getTime() + TTL_MS);
			expect(h.userSessionStore.create).toHaveBeenCalledWith({
				sid,
				sub: "u-1",
				authTime,
				expiresAt,
				claims,
				...passwordSessionAuthentication(),
				enrollmentFacts: { witness: "not_enrolled", mailAddress: "address" },
			});
			expect(h.subjectSessionIndex.addSid).toHaveBeenCalledWith("u-1", sid, expiresAt);
			expect(h.before.run).toHaveBeenCalledWith({ sid, sub: "u-1", expiresAt });
			expect(h.after.run).toHaveBeenCalledWith({ sid, sub: "u-1", expiresAt });
		});

		it("builds the reporter once, with the sid and the subject, before anything is written", async () => {
			const h = harness();

			await h.run();

			expect(h.reporterFactory).toHaveBeenCalledTimes(1);
			expect(h.reporterFactory).toHaveBeenCalledWith({ sid: createdSid(h), sub: "u-1" });
			expect(h.trace.indexOf("reporter")).toBeLessThan(h.trace.indexOf("create"));
		});

		it("writes the flags onto the regenerated session, with redirectTo only when the login carried one", async () => {
			const withRedirect = harness({}, { redirectTo: "https://app.example.com/welcome" });
			await withRedirect.run();
			expect(withRedirect.req.session).toMatchObject({
				id: "fresh",
				isAuthenticated: true,
				user,
				sid: createdSid(withRedirect),
				redirectTo: "https://app.example.com/welcome",
			});

			const without = harness();
			await without.run();
			expect(without.req.session).toMatchObject({ id: "fresh", isAuthenticated: true });
			expect(without.req.session).not.toHaveProperty("redirectTo");
		});

		it("without a UserSessionStore: no record, no index entry, no caller's step — the express session alone", async () => {
			const h = harness({}, { userSessionStore: false });

			const result = await h.run();

			expect(h.trace).toEqual(["reporter", "regenerate", "save"]);
			expect(result).toEqual({ outcome: "established", sid: undefined });
			expect(h.reporterFactory).toHaveBeenCalledWith({ sid: undefined, sub: "u-1" });
			expect(h.req.session).toMatchObject({ id: "fresh", isAuthenticated: true, user });
			expect(h.req.session).not.toHaveProperty("sid");
		});

		it("without a SubjectSessionIndex: no index write, and no index removal on rollback", async () => {
			const h = harness(
				{ regenerate: new Error("cookie store down") },
				{ subjectSessionIndex: false },
			);

			await h.run();

			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"before",
				"regenerate",
				"before-undo",
				"close",
				"delete",
			]);
		});

		it("reports a failed index write and lets the login proceed", async () => {
			const indexDown = new Error("index store down");
			const h = harness({ addSid: indexDown });

			const result = await h.run();

			expect(result).toEqual({ outcome: "established", sid: createdSid(h) });
			expect(h.reporter.subjectIndexWriteFailed).toHaveBeenCalledExactlyOnceWith(indexDown);
			expect(h.reporter.storeUnavailable).not.toHaveBeenCalled();
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"after",
				"save",
			]);
		});
	});

	describe("the session lifecycle, where it is wired", () => {
		it("opens the session's lifecycle record for the record's sid, subject and end, before the record is created", async () => {
			const h = harness({}, { lifecycle: "opened" });

			const result = await h.run();

			const sid = createdSid(h);
			expect(result).toEqual({ outcome: "established", sid });
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"after",
				"save",
			]);
			expect(h.sessionLifecycle.open).toHaveBeenCalledExactlyOnceWith(sid, {
				sub: "u-1",
				expiresAt: new Date(authTime.getTime() + TTL_MS),
			});
		});

		it.each(["unavailable", "refused"] as const)(
			"an open answered %s is the record's outage at create: nothing else written, nothing undone, the cookie session kept",
			async (outcome) => {
				const h = harness({}, { lifecycle: outcome });

				const result = await h.run();

				expect(result).toEqual({ outcome: "unavailable", store: "user_session", step: "create" });
				expect(h.trace).toEqual(["reporter", "open"]);
				expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
					"user_session",
					"create",
					expect.objectContaining({
						message: `the session lifecycle answered ${outcome} to the open`,
					}),
				);
				expect(h.reporter.cleanupFailed).not.toHaveBeenCalled();
				expect(h.req.session).toMatchObject({ id: "stale" });
			},
		);

		it("an open that throws is the record's outage at create, named as the lifecycle's, its error the cause", async () => {
			const thrown = new RangeError("session lifecycle: sub must be 1 to 512 characters");
			const h = harness({}, { lifecycle: thrown });

			const result = await h.run();

			expect(result).toEqual({ outcome: "unavailable", store: "user_session", step: "create" });
			expect(h.trace).toEqual(["reporter", "open"]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"user_session",
				"create",
				expect.objectContaining({
					message: "the session lifecycle could not open the session",
					cause: thrown,
				}),
			);
			expect(h.req.session).toMatchObject({ id: "stale" });
		});

		it("refuses a UserSessionStore without a session lifecycle, naming both, before anything is written", async () => {
			const h = harness({}, { lifecycle: false });

			await expect(h.run()).rejects.toThrow(
				/userSessionStore is wired, but sessionLifecycle is not/,
			);
			expect(h.trace).toEqual([]);
			expect(h.req.session).toMatchObject({ id: "stale" });
		});

		it("needs no session lifecycle without a UserSessionStore: a sessionless login is the express session alone", async () => {
			const h = harness({}, { userSessionStore: false, lifecycle: false });

			const result = await h.run();

			expect(result).toEqual({ outcome: "established", sid: undefined });
			expect(h.trace).toEqual(["reporter", "regenerate", "save"]);
		});

		it("the rollback closes the record it opened, for the record's sid, after the caller's steps are undone and before the record is deleted", async () => {
			const h = harness({ save: new Error("cookie store down") });

			const result = await h.run();

			expect(result).toEqual({ outcome: "unavailable", store: "cookie_session", step: "save" });
			expect(h.sessionLifecycle.close).toHaveBeenCalledExactlyOnceWith(
				createdSid(h),
				"session_logout",
			);
			expect(h.trace.slice(-5)).toEqual([
				"after-undo",
				"before-undo",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.cleanupFailed).not.toHaveBeenCalled();
		});

		it.each([
			["rejects", new Error("lifecycle store down")],
			["answers unavailable", "unavailable" as const],
		])(
			"a close that %s is the record's failed rollback step, named as the lifecycle's; the rest still run",
			async (_label, close) => {
				const h = harness({ save: new Error("cookie store down"), close });

				await h.run();

				expect(h.trace.slice(-3)).toEqual(["close", "delete", "removeSid"]);
				expect(h.reporter.cleanupFailed).toHaveBeenCalledExactlyOnceWith(
					"user_session",
					"delete",
					close instanceof Error
						? expect.objectContaining({
								message: "the session lifecycle could not close the session",
								cause: close,
							})
						: expect.objectContaining({
								message: "the session lifecycle answered unavailable to the close",
							}),
				);
			},
		);

		it("closes the record it opened when the record's create failed, after the outage is reported", async () => {
			const h = harness({ create: new Error("session store down") }, { traceReporter: true });

			await h.run();

			expect(h.sessionLifecycle.close).toHaveBeenCalledExactlyOnceWith(
				createdSid(h),
				"session_logout",
			);
			expect(h.trace).toEqual(["reporter", "open", "create", "outage", "close"]);
		});

		it("closes nothing when the open itself failed: no record was opened", async () => {
			const h = harness({}, { lifecycle: "unavailable" });

			await h.run();

			expect(h.sessionLifecycle.close).not.toHaveBeenCalled();
		});

		it("opens nothing without a UserSessionStore: there is no record", async () => {
			const h = harness({}, { userSessionStore: false, lifecycle: "opened" });

			await h.run();

			expect(h.sessionLifecycle.open).not.toHaveBeenCalled();
			expect(h.trace).toEqual(["reporter", "regenerate", "save"]);
		});
	});

	describe("the rollback ladder — each point a store can fail", () => {
		it("the record's create: reported, nothing else written, nothing undone, and the cookie session kept", async () => {
			const down = new Error("session store down");
			const h = harness({ create: down });

			const result = await h.run();

			expect(result).toEqual({ outcome: "unavailable", store: "user_session", step: "create" });
			expect(h.trace).toEqual(["reporter", "open", "create", "close"]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"user_session",
				"create",
				down,
			);
			expect(h.reporter.cleanupFailed).not.toHaveBeenCalled();
			expect(h.req.session).toMatchObject({ id: "stale" });
		});

		it("the caller's step before the regeneration: not undone itself; the record and its index entry are; the cookie session kept", async () => {
			const down = new Error("federation index down");
			const h = harness({ before: down });

			const result = await h.run();

			expect(result).toEqual({
				outcome: "unavailable",
				store: "session_federation_index",
				step: "add",
			});
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"session_federation_index",
				"add",
				down,
			);
			expect(h.req.session).toMatchObject({ id: "stale" });
		});

		it("the regeneration: the caller's step undone first, then the record, then its index entry; the cookie session dropped", async () => {
			const down = new Error("cookie store down");
			const h = harness({ regenerate: down });

			const result = await h.run();

			expect(result).toEqual({
				outcome: "unavailable",
				store: "cookie_session",
				step: "regenerate",
			});
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"before-undo",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"cookie_session",
				"regenerate",
				down,
			);
			expect(h.req.session).toBeUndefined();
		});

		it("the caller's step after the regeneration: not undone itself; the earlier step, the record and its index entry are; the cookie session dropped", async () => {
			const down = new Error("token store down");
			const h = harness({ after: down });

			const result = await h.run();

			expect(result).toEqual({ outcome: "unavailable", store: "federation_token", step: "attach" });
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"after",
				"before-undo",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"federation_token",
				"attach",
				down,
			);
			expect(h.req.session).toBeUndefined();
		});

		it("the save: every write undone in reverse order, the index entry last; the cookie session dropped", async () => {
			const down = new Error("cookie store down");
			const h = harness({ save: down });

			const result = await h.run();

			expect(result).toEqual({ outcome: "unavailable", store: "cookie_session", step: "save" });
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"after",
				"save",
				"after-undo",
				"before-undo",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"cookie_session",
				"save",
				down,
			);
			expect(h.req.session).toBeUndefined();
		});

		it("a save that throws synchronously — a store serialising the record throws there — is the store's failure: the full ladder, and the cookie session dropped", async () => {
			const thrown = new TypeError("Do not know how to serialize a BigInt");
			const h = harness({ saveThrows: thrown });

			const result = await h.run();

			expect(result).toEqual({ outcome: "unavailable", store: "cookie_session", step: "save" });
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"after",
				"save",
				"after-undo",
				"before-undo",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"cookie_session",
				"save",
				thrown,
			);
			expect(h.req.session).toBeUndefined();
		});

		it("a regenerate that throws synchronously is the store's failure too: the ladder, and the cookie session dropped", async () => {
			const thrown = new Error("cookie store threw");
			const h = harness({ regenerateThrows: thrown });

			const result = await h.run();

			expect(result).toEqual({
				outcome: "unavailable",
				store: "cookie_session",
				step: "regenerate",
			});
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"before-undo",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.storeUnavailable).toHaveBeenCalledExactlyOnceWith(
				"cookie_session",
				"regenerate",
				thrown,
			);
			expect(h.req.session).toBeUndefined();
		});

		it("a rollback step that fails is reported, in order, and the rest still run", async () => {
			const tokenDown = new Error("token store down");
			const sessionDown = new Error("session store down");
			const indexDown = new Error("subject index down");
			const h = harness({
				save: new Error("cookie store down"),
				afterUndo: tokenDown,
				delete: sessionDown,
				removeSid: indexDown,
			});

			const result = await h.run();

			expect(result).toEqual({ outcome: "unavailable", store: "cookie_session", step: "save" });
			expect(h.trace.slice(-5)).toEqual([
				"after-undo",
				"before-undo",
				"close",
				"delete",
				"removeSid",
			]);
			expect(h.reporter.cleanupFailed.mock.calls).toEqual([
				["federation_token", "delete", tokenDown],
				["user_session", "delete", sessionDown],
				["subject_session_index", "remove_sid", indexDown],
			]);
		});

		it("reports the outage before any rollback step runs — a failure before the regeneration", async () => {
			const h = harness({ before: new Error("federation index down") }, { traceReporter: true });

			await h.run();

			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"outage",
				"close",
				"delete",
				"removeSid",
			]);
		});

		it("reports the outage before any rollback step runs, and each rollback step that fails as it happens — a failure at the save", async () => {
			const h = harness(
				{
					save: new Error("cookie store down"),
					afterUndo: new Error("token store down"),
					delete: new Error("session store down"),
					removeSid: new Error("subject index down"),
				},
				{ traceReporter: true },
			);

			await h.run();

			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"before",
				"regenerate",
				"after",
				"save",
				"outage",
				"after-undo",
				"cleanup-failed",
				"before-undo",
				"close",
				"delete",
				"cleanup-failed",
				"removeSid",
				"cleanup-failed",
			]);
		});

		it("a step that declares no undo is left as it is", async () => {
			const h = harness({ regenerate: new Error("cookie store down") }, { steps: false });
			const stepWithoutUndo: EstablishSessionStep<"session_federation_index", "add"> = {
				store: "session_federation_index",
				step: "add",
				run: vi.fn(async () => {
					h.trace.push("plain");
				}),
			};

			const result = await establishSession(await passwordEstablishment(), {
				req: h.req as unknown as Request,
				userSessionStore: h.userSessionStore,
				subjectSessionIndex: h.subjectSessionIndex,
				sessionLifecycle: h.sessionLifecycle,
				sessionTtlMs: TTL_MS,
				beforeRegenerate: [stepWithoutUndo],
				reporter: h.reporterFactory,
			});

			expect(result).toEqual({
				outcome: "unavailable",
				store: "cookie_session",
				step: "regenerate",
			});
			expect(h.trace).toEqual([
				"reporter",
				"open",
				"create",
				"addSid",
				"plain",
				"regenerate",
				"close",
				"delete",
				"removeSid",
			]);
		});
	});
});
