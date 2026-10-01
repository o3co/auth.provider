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
 * A first binding in a session (the MFA ADR's D12, D24, D25; F4 step 3): an
 * action graded `credential_change` — a first factor from the account page
 * (`mfa.manage`), a passkey (`webauthn.register`), a linked identity
 * (`session.link`) — for a subject that holds no record that may count.
 * The session's recorded facts come first: none recorded sends it to log
 * in, and a witness that says the subject enrolled, or says nothing
 * readable, is an outage recorded as `mfa.enrollment_state_inconsistent`.
 * Then a recent primary, then the one gate — whose proof is the one given
 * in that session, while it stands. Password and federated sessions alike,
 * under either mode, through admission as each consumer asks it.
 */

import {
	type AuditEvent,
	admitSession,
	cookieClaim,
	createMemoryMfaTransactionStore,
	DEFAULT_CLOCK_SKEW_MS,
	type Logger,
	type MailAddressFact,
	type MfaEnrollmentWitness,
	type MfaFactor,
	type MfaFactorRecord,
	type MfaTransactionStore,
	type RequirementVerdict,
	readAcrTable,
	requirementSession,
	type SessionEnrollmentFacts,
	type SessionRequirement,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { resolverForTests } from "@o3co/auth-provider-core/testing";
import { describe, expect, it, type Mock, vi } from "vitest";
import type { RequireEmailProof } from "#/firstBinding.mjs";
import { createMfaRequirement } from "#/requirement.mjs";
import { createLoginTransactions } from "#/transactions.mjs";
import {
	FACTORS,
	factorRecord,
	factorStoreHolding,
	resolverOver,
	SEALING,
	stubFactor,
} from "./requirementHarness.mjs";

const ISSUER = "https://auth.example";
const PAGE = { url: "/mfa", params: {} };
const SUBJECT = "u-alice";
const SID = "sid-alice";

/** A logger whose `warn` is a spy and every other level does nothing. */
function silentLogger(): Logger & { readonly warn: Mock } {
	const logger = {
		trace: () => {},
		debug: () => {},
		info: () => {},
		warn: vi.fn(),
		error: () => {},
		fatal: () => {},
		child: () => logger,
	};
	return logger as unknown as Logger & { readonly warn: Mock };
}

/** The three actions a first binding in a session is admitted for, as their packages register them. */
const FIRST_BINDINGS = {
	"mfa.manage": { grade: "credential_change" },
	"webauthn.register": { grade: "credential_change" },
	"session.link": { grade: "credential_change" },
} as const;
type FirstBindingAction = keyof typeof FIRST_BINDINGS;
const ACTIONS = Object.keys(FIRST_BINDINGS) as FirstBindingAction[];

const MET: RequirementVerdict = { outcome: "met" };
const REAUTHENTICATE: RequirementVerdict = { outcome: "reauthenticate" };
const STEP_UP: RequirementVerdict = { outcome: "step_up", whenStillUnmet: "reauthenticate" };

/** What a login records when the account is not enrolled and has an address the provider reads. */
const facts = (
	witness: MfaEnrollmentWitness = "not_enrolled",
	mailAddress: MailAddressFact = "address",
): SessionEnrollmentFacts => ({ witness, mailAddress });

type Kind = "pwd" | "fed";

/**
 * A live session of `SUBJECT`, signed in `ageMs` before now, recording
 * `recorded`: a password login with a second factor verified a minute ago
 * (which every mode's baseline meets), or a federated one.
 */
function sessionOf(
	kind: Kind,
	recorded: SessionEnrollmentFacts | undefined,
	options: {
		readonly ageMs?: number;
		readonly sid?: string;
		/** A password session's second factor this long ago; its sign-in's age by default, and none when `null`. */
		readonly mfaAgeMs?: number | null;
	} = {},
): UserSession {
	const now = Date.now();
	const authTime = new Date(now - (options.ageMs ?? 60_000));
	const mfaAt =
		options.mfaAgeMs === null
			? undefined
			: options.mfaAgeMs === undefined
				? authTime
				: new Date(now - options.mfaAgeMs);
	return {
		sid: options.sid ?? SID,
		sub: SUBJECT,
		authTime,
		createdAt: authTime,
		expiresAt: new Date(now + 3_600_000),
		claims: {},
		...(kind === "pwd"
			? {
					amr: mfaAt === undefined ? ["pwd"] : ["pwd", "otp", "mfa"],
					authentication: {
						primary: "pwd",
						federation: undefined,
						upstreamAmr: undefined,
						mfaAt,
					},
				}
			: {
					amr: ["fed"],
					authentication: {
						primary: "fed",
						federation: "google",
						upstreamAmr: undefined,
						mfaAt: undefined,
					},
				}),
		...(recorded === undefined ? {} : { enrollmentFacts: recorded }),
	};
}

interface BuildOptions {
	readonly mode?: "optional" | "required";
	readonly requireEmailProof?: RequireEmailProof;
	readonly mailWired?: boolean;
	readonly records?: MfaFactorRecord[];
	readonly factors?: MfaFactor[];
	readonly transactionStore?: MfaTransactionStore;
	readonly events?: AuditEvent[];
	readonly logger?: Logger;
}

/** The requirement over `options`: TOTP and recovery codes installed, a mail sender wired, `when-mail`, no record held. */
function build(options: BuildOptions = {}) {
	const transactionStore = options.transactionStore ?? createMemoryMfaTransactionStore();
	const events = options.events;
	const requirement = createMfaRequirement({
		mode: options.mode ?? "optional",
		factors: resolverOver(options.factors ?? [FACTORS.totp(), FACTORS.recovery()]),
		factorStore: factorStoreHolding(...(options.records ?? [])),
		transactions: createLoginTransactions({ store: transactionStore, ttlSeconds: 600 }),
		stepUpPage: PAGE,
		stepUpRecordable: true,
		recentMfaMaxAgeSeconds: 300,
		logger: options.logger ?? silentLogger(),
		...(events === undefined
			? {}
			: { auditSink: { kind: "recording", record: async (event) => void events.push(event) } }),
		firstBinding: {
			requireEmailProof: options.requireEmailProof ?? "when-mail",
			mailWired: options.mailWired ?? true,
		},
		emailProofRequiredAtNextBinding: (subject) =>
			transactionStore.emailProofRequiredAtNextBinding(subject),
		sessionEmailProofAt: (subject, sid, nowMs) =>
			transactionStore.sessionEmailProofAt(subject, sid, nowMs),
		firstBindingAt: (subject, nowMs) => transactionStore.firstBindingAt(subject, nowMs),
		sealing: SEALING,
	});
	return { requirement, transactionStore };
}

/** What admission hands the requirement for `session`, admitted for `action`. */
const inputFor = (session: UserSession, action: FirstBindingAction = "mfa.manage") => ({
	session: {
		sid: session.sid,
		sub: session.sub,
		authTime: session.authTime,
		expiresAt: session.expiresAt,
		...(session.enrollmentFacts === undefined ? {} : { enrollmentFacts: session.enrollmentFacts }),
	},
	authentication: requirementSession(session),
	carrier: "cookie" as const,
	subject: session.sub,
	action: { name: action, ...FIRST_BINDINGS[action] },
	asks: undefined,
	now: new Date(),
});

const storeHolding = (session: UserSession): UserSessionStore => ({
	kind: "test",
	create: async () => {},
	get: async (sid) => (sid === session.sid ? session : null),
	delete: async () => {},
});

/** `session` admitted for `action` through core's admission, as the consumer that registers it asks. */
const admit = (requirement: SessionRequirement, session: UserSession, action: FirstBindingAction) =>
	admitSession(
		{
			userSessionStore: storeHolding(session),
			subjectRevocation: undefined,
			requirements: resolverForTests([requirement], { issuer: ISSUER, actions: FIRST_BINDINGS }),
			acrTable: readAcrTable({}),
			logger: undefined,
			auditSink: undefined,
		},
		{
			claim: cookieClaim({
				session: { isAuthenticated: true, sid: session.sid, user: { id: session.sub } },
			}),
			action,
		},
	);

/** The sessions whose baseline `mode` meets: a password session with a second factor, a federated one. */
const KINDS: readonly Kind[] = ["pwd", "fed"];
const MODES = ["optional", "required"] as const;

/** Records `SUBJECT`'s account-email proof in `sid`, standing five minutes. */
const proved = (store: MfaTransactionStore, sid: string = SID, subject: string = SUBJECT) => {
	const now = Date.now();
	return store.recordSessionEmailProof(subject, sid, now, now + 300_000);
};

describe("a subject with no counting factor, in a session that recorded no facts", () => {
	for (const mode of MODES) {
		for (const kind of KINDS) {
			it(`${mode} · ${kind}: is sent to log in again for each first binding, reading neither D25's flag nor a proof`, async () => {
				const transactionStore = createMemoryMfaTransactionStore();
				const flag = vi.spyOn(transactionStore, "emailProofRequiredAtNextBinding");
				const proof = vi.spyOn(transactionStore, "sessionEmailProofAt");
				const { requirement } = build({ mode, transactionStore });
				await proved(transactionStore);
				for (const action of ACTIONS) {
					expect(
						await requirement.admit(inputFor(sessionOf(kind, undefined), action)),
						action,
					).toEqual(REAUTHENTICATE);
					expect(
						await admit(requirement, sessionOf(kind, undefined), action),
						action,
					).toMatchObject({
						outcome: "reauthenticate",
						requirement: "mfa",
					});
				}
				expect(flag).not.toHaveBeenCalled();
				expect(proof).not.toHaveBeenCalled();
			});
		}
	}
});

describe("a subject with no counting factor whose session recorded a witness that says it enrolled, or nothing readable", () => {
	for (const mode of MODES) {
		for (const kind of KINDS) {
			it(`${mode} · ${kind}: sends the session to log in again for each first binding, recording nothing and reading nothing else`, async () => {
				for (const witness of ["enrolled", "malformed"] as const) {
					const events: AuditEvent[] = [];
					const transactionStore = createMemoryMfaTransactionStore();
					const flag = vi.spyOn(transactionStore, "emailProofRequiredAtNextBinding");
					const proof = vi.spyOn(transactionStore, "sessionEmailProofAt");
					const mark = vi.spyOn(transactionStore, "firstBindingAt");
					const { requirement } = build({ mode, transactionStore, events });
					for (const action of ACTIONS) {
						const session = sessionOf(kind, facts(witness));
						expect(await requirement.admit(inputFor(session, action)), action).toEqual(
							REAUTHENTICATE,
						);
					}
					expect(events).toEqual([]);
					expect(flag).not.toHaveBeenCalled();
					expect(proof).not.toHaveBeenCalled();
					expect(mark).not.toHaveBeenCalled();
				}
			});
		}
	}

	it("compares the witness with the records that may count: recovery codes alone, or a kind every installed factor declares non-counting, beside it send the session to log in again", async () => {
		const paper = stubFactor("paper", ["paper"], { counting: false });
		for (const records of [
			[factorRecord(SUBJECT, "recovery_code")],
			[factorRecord(SUBJECT, "paper")],
			[factorRecord(SUBJECT, "recovery_code", "f-1"), factorRecord(SUBJECT, "paper", "f-2")],
		]) {
			const { requirement } = build({
				records,
				factors: [FACTORS.totp(), FACTORS.recovery(), paper],
			});
			for (const action of ACTIONS) {
				expect(
					await requirement.admit(inputFor(sessionOf("fed", facts("enrolled")), action)),
					JSON.stringify(records.map((record) => record.kind)),
				).toEqual(REAUTHENTICATE);
			}
		}
	});

	it("reads no witness while a record that may count stands — a counting factor, or a kind no installed factor declares — and holds the session to recent MFA", async () => {
		for (const records of [
			[factorRecord(SUBJECT, "totp")],
			[factorRecord(SUBJECT, "retired-kind")],
		]) {
			const events: AuditEvent[] = [];
			const { requirement } = build({ records, events });
			const withoutSecondFactor = sessionOf("fed", facts("enrolled"));
			const withSecondFactor = sessionOf("pwd", facts("malformed"));
			expect(await requirement.admit(inputFor(withoutSecondFactor))).toEqual(STEP_UP);
			expect(await requirement.admit(inputFor(withSecondFactor))).toEqual(MET);
			expect(events).toEqual([]);
		}
	});
});

describe("a subject with no counting factor whose primary is older than mfa.manage.maxAgeSeconds", () => {
	for (const mode of MODES) {
		it(`${mode}: is sent to log in again for each first binding, before the gate is asked`, async () => {
			const transactionStore = createMemoryMfaTransactionStore();
			const flag = vi.spyOn(transactionStore, "emailProofRequiredAtNextBinding");
			const { requirement } = build({ mode, transactionStore });
			for (const action of ACTIONS) {
				const stale = sessionOf("fed", facts(), { ageMs: 301_000 });
				expect(await requirement.admit(inputFor(stale, action)), action).toEqual(REAUTHENTICATE);
			}
			expect(flag).not.toHaveBeenCalled();
		});

		it(`${mode}: is sent to log in again even with a second factor verified in the session inside the window — a first binding needs a recent primary`, async () => {
			const { requirement } = build({ mode });
			for (const action of ACTIONS) {
				const stale = sessionOf("pwd", facts(), { ageMs: 301_000, mfaAgeMs: 60_000 });
				expect(await requirement.admit(inputFor(stale, action)), action).toEqual(REAUTHENTICATE);
			}
		});

		it(`${mode}: is still an outage when its session's witness says it enrolled: the witness is read before the primary's age`, async () => {
			const events: AuditEvent[] = [];
			const { requirement } = build({ mode, events });
			const stale = sessionOf("fed", facts("enrolled"), { ageMs: 301_000 });
			await expect(requirement.admit(inputFor(stale))).rejects.toMatchObject({
				reason: "mfa_enrollment_state_inconsistent",
			});
			expect(await admit(requirement, stale, "session.link")).toEqual({
				outcome: "unavailable",
				store: "mfa",
			});
			expect(events).toHaveLength(2);
		});
	}
});

describe("under required, a password session without a second factor whose subject holds no counting factor", () => {
	it("is sent to log in again for each first binding — the login binds the first factor — asking no gate and reading no proof", async () => {
		const transactionStore = createMemoryMfaTransactionStore();
		const flag = vi.spyOn(transactionStore, "emailProofRequiredAtNextBinding");
		const proof = vi.spyOn(transactionStore, "sessionEmailProofAt");
		const { requirement } = build({ mode: "required", transactionStore });
		await proved(transactionStore);
		const session = sessionOf("pwd", facts(), { mfaAgeMs: null });
		for (const action of ACTIONS) {
			expect(await requirement.admit(inputFor(session, action)), action).toEqual(REAUTHENTICATE);
			expect(await admit(requirement, session, action), action).toMatchObject({
				outcome: "reauthenticate",
				requirement: "mfa",
			});
		}
		expect(flag).not.toHaveBeenCalled();
		expect(proof).not.toHaveBeenCalled();
	});

	it("is a first binding under optional, and one whose subject holds a counting factor is stepped up under required", async () => {
		const session = sessionOf("pwd", facts(), { mfaAgeMs: null });
		expect(await build({ mode: "optional" }).requirement.admit(inputFor(session))).toEqual(STEP_UP);
		const holding = build({ mode: "required", records: [factorRecord(SUBJECT, "totp")] });
		expect(await holding.requirement.admit(inputFor(session))).toEqual(STEP_UP);
	});
});

describe("the gate over a first binding in a session", () => {
	type Gate = "bind" | "prove" | "unprovable";
	interface Row {
		readonly requireEmailProof: RequireEmailProof;
		readonly mailWired: boolean;
		readonly mailAddress: MailAddressFact;
		readonly flag: boolean;
		readonly gate: Gate;
	}
	const rows: readonly Row[] = [
		{
			requireEmailProof: "when-mail",
			mailWired: true,
			mailAddress: "address",
			flag: false,
			gate: "prove",
		},
		{
			requireEmailProof: "when-mail",
			mailWired: true,
			mailAddress: "none",
			flag: false,
			gate: "bind",
		},
		{
			requireEmailProof: "when-mail",
			mailWired: true,
			mailAddress: "unreadable",
			flag: false,
			gate: "unprovable",
		},
		{
			requireEmailProof: "when-mail",
			mailWired: false,
			mailAddress: "address",
			flag: false,
			gate: "bind",
		},
		{
			requireEmailProof: "when-mail",
			mailWired: false,
			mailAddress: "unreadable",
			flag: false,
			gate: "bind",
		},
		{
			requireEmailProof: "always",
			mailWired: true,
			mailAddress: "address",
			flag: false,
			gate: "prove",
		},
		{
			requireEmailProof: "always",
			mailWired: true,
			mailAddress: "none",
			flag: false,
			gate: "unprovable",
		},
		{
			requireEmailProof: "always",
			mailWired: true,
			mailAddress: "unreadable",
			flag: false,
			gate: "unprovable",
		},
		{
			requireEmailProof: "always",
			mailWired: false,
			mailAddress: "address",
			flag: false,
			gate: "unprovable",
		},
		{
			requireEmailProof: "never",
			mailWired: true,
			mailAddress: "address",
			flag: false,
			gate: "bind",
		},
		{
			requireEmailProof: "never",
			mailWired: true,
			mailAddress: "unreadable",
			flag: false,
			gate: "bind",
		},
		{
			requireEmailProof: "never",
			mailWired: false,
			mailAddress: "none",
			flag: false,
			gate: "bind",
		},
		{
			requireEmailProof: "never",
			mailWired: true,
			mailAddress: "address",
			flag: true,
			gate: "prove",
		},
		{
			requireEmailProof: "never",
			mailWired: false,
			mailAddress: "address",
			flag: true,
			gate: "unprovable",
		},
		{
			requireEmailProof: "when-mail",
			mailWired: true,
			mailAddress: "none",
			flag: true,
			gate: "unprovable",
		},
		{
			requireEmailProof: "when-mail",
			mailWired: false,
			mailAddress: "address",
			flag: true,
			gate: "unprovable",
		},
		{
			requireEmailProof: "when-mail",
			mailWired: true,
			mailAddress: "address",
			flag: true,
			gate: "prove",
		},
	];
	const name = (row: Row) =>
		`${row.requireEmailProof}, ${row.mailWired ? "a sender" : "no sender"}, ${row.mailAddress}${row.flag ? ", D25's flag" : ""} → ${row.gate}`;

	for (const mode of MODES) {
		for (const kind of KINDS) {
			it.each(rows.map((row) => ({ ...row, row: name(row) })))(
				`${mode} · ${kind} · $row`,
				async ({ requireEmailProof, mailWired, mailAddress, flag, gate }) => {
					const { requirement, transactionStore } = build({ mode, requireEmailProof, mailWired });
					if (flag) await transactionStore.requireEmailProofAtNextBinding(SUBJECT);
					const session = sessionOf(kind, facts("not_enrolled", mailAddress));
					for (const action of ACTIONS) {
						const before = await admit(requirement, session, action);
						if (gate === "bind") {
							expect(before, action).toMatchObject({ outcome: "admitted" });
						} else {
							expect(before, action).toMatchObject({
								outcome: "step_up",
								requirement: "mfa",
								page: { href: `${ISSUER}/mfa` },
								whenStillUnmet: "reauthenticate",
							});
						}
					}
					// A proof given in another session of the subject, or by another subject in this one, admits nothing.
					await proved(transactionStore, "sid-other");
					await proved(transactionStore, SID, "u-bob");
					for (const action of ACTIONS) {
						expect((await admit(requirement, session, action)).outcome, action).toBe(
							gate === "bind" ? "admitted" : "step_up",
						);
					}
					// The proof given in this session admits a proof the gate asks for, and never one nobody can give.
					await proved(transactionStore);
					for (const action of ACTIONS) {
						expect((await admit(requirement, session, action)).outcome, action).toBe(
							gate === "unprovable" ? "step_up" : "admitted",
						);
						expect(await requirement.admit(inputFor(session, action)), action).toEqual(
							gate === "unprovable" ? STEP_UP : MET,
						);
					}
				},
			);
		}
	}

	it("reads the proof of the session admitted, at admission's clock", async () => {
		const transactionStore = createMemoryMfaTransactionStore();
		const proof = vi.spyOn(transactionStore, "sessionEmailProofAt");
		const { requirement } = build({ transactionStore });
		const input = inputFor(sessionOf("pwd", facts()));
		await requirement.admit(input);
		expect(proof.mock.calls).toEqual([[SUBJECT, SID, input.now.getTime()]]);
	});

	it("reads no proof where the gate asks none, and none where nobody could give it", async () => {
		for (const [options, mailAddress] of [
			[{ requireEmailProof: "never" as const }, "address"],
			[{ mailWired: false }, "address"],
			[{}, "none"],
			[{}, "unreadable"],
		] as const) {
			const transactionStore = createMemoryMfaTransactionStore();
			const proof = vi.spyOn(transactionStore, "sessionEmailProofAt");
			const { requirement } = build({ ...options, transactionStore });
			await requirement.admit(inputFor(sessionOf("pwd", facts("not_enrolled", mailAddress))));
			expect(proof, JSON.stringify([options, mailAddress])).not.toHaveBeenCalled();
		}
	});

	it("says at warn, at each admission, when the proof it asks for cannot be given — the subject and why, never an address", async () => {
		for (const [options, mailAddress, reason] of [
			[{ requireEmailProof: "always" as const, mailWired: false }, "address", "no_sender"],
			[{ requireEmailProof: "always" as const }, "none", "no_address"],
			[{}, "unreadable", "unreadable_address"],
		] as const) {
			const logger = silentLogger();
			const { requirement } = build({ ...options, logger });
			const session = sessionOf("fed", facts("not_enrolled", mailAddress));
			await requirement.admit(inputFor(session, "webauthn.register"));
			await requirement.admit(inputFor(session, "session.link"));
			expect(logger.warn.mock.calls, reason).toEqual([
				[{ sub: SUBJECT, reason }, "mfa_email_proof_unprovable"],
				[{ sub: SUBJECT, reason }, "mfa_email_proof_unprovable"],
			]);
		}
	});

	it("says nothing where it asks a proof that can be given, or none", async () => {
		const logger = silentLogger();
		const { requirement } = build({ logger });
		await requirement.admit(inputFor(sessionOf("pwd", facts("not_enrolled", "address"))));
		await requirement.admit(inputFor(sessionOf("pwd", facts("not_enrolled", "none"))));
		expect(logger.warn).not.toHaveBeenCalled();
	});

	it("throws where D25's flag cannot be read, or reads other than a boolean — admission answers unavailable", async () => {
		for (const answer of [
			() => Promise.reject(new Error("transaction store unreachable")),
			() => Promise.resolve("true"),
		]) {
			const transactionStore = createMemoryMfaTransactionStore();
			vi.spyOn(transactionStore, "emailProofRequiredAtNextBinding").mockImplementation(
				answer as never,
			);
			const { requirement } = build({ transactionStore });
			const session = sessionOf("pwd", facts());
			await expect(requirement.admit(inputFor(session))).rejects.toBeInstanceOf(Error);
			expect(await admit(requirement, session, "session.link")).toEqual({
				outcome: "unavailable",
				store: "mfa",
			});
		}
	});

	it("reads a proof older than mfa.manage.maxAgeSeconds and the clock skew as none — the epoch among them — and one inside as standing", async () => {
		const at = (answer: (now: number) => number) => {
			const transactionStore = createMemoryMfaTransactionStore();
			vi.spyOn(transactionStore, "sessionEmailProofAt").mockImplementation(async (_s, _sid, now) =>
				answer(now),
			);
			return build({ transactionStore }).requirement.admit(inputFor(sessionOf("pwd", facts())));
		};
		expect(await at(() => 0)).toEqual(STEP_UP);
		expect(await at((now) => now - 300_000 - DEFAULT_CLOCK_SKEW_MS - 1)).toEqual(STEP_UP);
		expect(await at((now) => now - 300_000 - DEFAULT_CLOCK_SKEW_MS)).toEqual(MET);
		expect(await at((now) => now - 1_000)).toEqual(MET);
	});

	it("throws where the session's proof cannot be read, or reads other than a time or none — never admitted, never stepped up", async () => {
		for (const answer of [
			() => Promise.reject(new Error("transaction store unreachable")),
			() => Promise.resolve("now"),
			() => Promise.resolve(Date.now() + 86_400_000),
			() => Promise.resolve(Number.NaN),
		]) {
			const transactionStore = createMemoryMfaTransactionStore();
			vi.spyOn(transactionStore, "sessionEmailProofAt").mockImplementation(answer as never);
			const { requirement } = build({ transactionStore });
			const session = sessionOf("fed", facts());
			await expect(requirement.admit(inputFor(session))).rejects.toBeInstanceOf(Error);
			expect(await admit(requirement, session, "webauthn.register")).toEqual({
				outcome: "unavailable",
				store: "mfa",
			});
		}
	});
});

describe("a subject with no counting factor whose first-binding mark distrusts the session", () => {
	/** The requirement with no proof asked, `SUBJECT`'s mark answered by `answer` at the time asked about. */
	const markedAt = (answer: (now: number) => unknown) => {
		const transactionStore = createMemoryMfaTransactionStore();
		const read = vi
			.spyOn(transactionStore, "firstBindingAt")
			.mockImplementation(async (_subject, now) => answer(now) as number | null);
		return { ...build({ transactionStore, requireEmailProof: "never" }), read };
	};

	for (const mode of MODES) {
		for (const kind of KINDS) {
			it(`${mode} · ${kind}: sends a session authenticated no later than the mark and the clock skew to log in again, for each first binding, asking no gate`, async () => {
				const transactionStore = createMemoryMfaTransactionStore();
				const flag = vi.spyOn(transactionStore, "emailProofRequiredAtNextBinding");
				const { requirement } = build({ mode, transactionStore });
				const session = sessionOf(kind, facts());
				// Another session of the subject bound its first factor after this one signed in.
				const now = Date.now();
				await transactionStore.noteFirstBinding(SUBJECT, now, now + 1_800_000);
				for (const action of ACTIONS) {
					expect(await requirement.admit(inputFor(session, action)), action).toEqual(
						REAUTHENTICATE,
					);
					expect(await admit(requirement, session, action), action).toMatchObject({
						outcome: "reauthenticate",
						requirement: "mfa",
					});
				}
				expect(flag).not.toHaveBeenCalled();
			});
		}
	}

	it("refuses a session authenticated at the mark plus the clock skew, and admits one a millisecond later", async () => {
		const session = sessionOf("pwd", facts());
		const authTime = session.authTime.getTime();
		const at = markedAt(() => authTime - DEFAULT_CLOCK_SKEW_MS);
		expect(await at.requirement.admit(inputFor(session))).toEqual(REAUTHENTICATE);
		const after = markedAt(() => authTime - DEFAULT_CLOCK_SKEW_MS - 1);
		expect(await after.requirement.admit(inputFor(session))).toEqual(MET);
		const none = markedAt(() => null);
		expect(await none.requirement.admit(inputFor(session))).toEqual(MET);
	});

	it("reads the mark of the session's subject at admission's clock, once its witness and its recent primary hold", async () => {
		const { requirement, read } = markedAt(() => null);
		const input = inputFor(sessionOf("fed", facts()));
		await requirement.admit(input);
		expect(read.mock.calls).toEqual([[SUBJECT, input.now.getTime()]]);

		const stale = markedAt(() => null);
		await stale.requirement.admit(inputFor(sessionOf("fed", facts(), { ageMs: 301_000 })));
		await expect(
			stale.requirement.admit(inputFor(sessionOf("fed", facts("enrolled")))),
		).rejects.toMatchObject({ name: "MfaEnrollmentStateInconsistentError" });
		expect(stale.read).not.toHaveBeenCalled();
	});

	it("throws where the mark cannot be read, or reads other than a time or none — never admitted", async () => {
		for (const answer of [
			() => Promise.reject(new Error("transaction store unreachable")),
			() => "now",
			(now: number) => now + DEFAULT_CLOCK_SKEW_MS + 1,
			() => Number.NaN,
			(now: number) => now - 0.5,
		]) {
			const { requirement } = markedAt(answer as (now: number) => unknown);
			const session = sessionOf("pwd", facts());
			await expect(requirement.admit(inputFor(session))).rejects.toBeInstanceOf(Error);
			expect(await admit(requirement, session, "mfa.manage")).toEqual({
				outcome: "unavailable",
				store: "mfa",
			});
		}
	});
});
