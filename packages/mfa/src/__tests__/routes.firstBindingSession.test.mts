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
 * What a first binding makes of the sign-in it is made in (the MFA ADR's
 * D24, D25), through the composed application. One made with the
 * account-email proof counts at once: the login it completes is established
 * with the factor's `amr` and `mfaAt`, and the session it is made in is
 * escalated by it. One made without the proof — none asked, under
 * `when-mail` without a sender or an address, or under `never` — counts from
 * the next sign-in that uses the factor: a login's answers the factor and its
 * codes and establishes no session, and a session's is left as it was, able
 * to step up with the factor it bound. A binding after an operator reset
 * follows the proof the reset's flag asked for.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	defineModule,
	type MailSender,
	MFA_AMR,
	type Module,
	OTP_AMR,
	PASSWORD_AMR,
	type SubjectRevocationReport,
	type SubjectRevocationService,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createRecordingMailSender,
	type RecordingMailSender,
} from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { createMfaReset } from "#/reset.mjs";
import { mfaResetModule } from "#/resetModule.mjs";
import { decodeBase32 } from "#/totp/base32.mjs";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	sessionIdSet,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginEnrollment,
	beginFirstBinding,
	beginLogin,
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
	giveEmailProof,
	recordingAuditSink,
	seedTotp,
	signIn,
	stepUp,
	T0,
	thawClock,
	totpCode,
	totpProofOf,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
	vi.restoreAllMocks();
});

const LOGIN_REQUIRED = { error: "login_required", error_description: "Log in again" };

/** How a first binding's gate is set up: the setting, whether a sender is wired, whether alice has an address. */
interface Setup {
	readonly mode?: "optional" | "required";
	readonly requireEmailProof?: "when-mail" | "always" | "never";
	readonly sender?: boolean;
	readonly withoutAddress?: boolean;
	readonly extraModules?: readonly Module[];
}

/** The three ways a first binding is made without the account-email proof. */
const UNPROVEN: readonly (readonly [string, Setup])[] = [
	["under when-mail without a mail sender", { sender: false }],
	["under when-mail for an account without an address", { withoutAddress: true }],
	["under never, with a mail sender and an address", { requireEmailProof: "never" }],
];

/** Boots `mode` (required by default) with a recording sender unless `sender` is false. */
async function composed(setup: Setup = {}) {
	const entries = directoryEntries();
	if (setup.withoutAddress === true) delete entries.get(ALICE.username)?.email;
	const sender: RecordingMailSender | null =
		setup.sender === false ? null : createRecordingMailSender();
	const factorStore = createMemoryMfaFactorStore();
	const transactionStore = createMemoryMfaTransactionStore();
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor(setup.mode ?? "required", {
			enrollment: { requireEmailProof: setup.requireEmailProof ?? "when-mail" },
		}),
		factorStore,
		transactionStore,
		auditSink: audit,
		userRepository: new WitnessingUserRepository(entries),
		...(sender === null ? {} : { mailSender: sender as MailSender }),
		...(setup.extraModules === undefined ? {} : { extraModules: setup.extraModules }),
	});
	return {
		...booted,
		factorStore,
		transactionStore,
		userSessionStore: booted.userSessionStore as UserSessionStore,
		audit,
		sender,
	};
}

type Composed = Awaited<ReturnType<typeof composed>>;

/** Alice's TOTP record and its secret, as the binding answered and stored them. */
async function boundTotp(
	booted: Composed,
	secret: unknown,
): Promise<{ readonly id: string; readonly key: Buffer; readonly binding: unknown }> {
	const record = (await booted.factorStore.list(ALICE.id)).find((entry) => entry.kind === "totp");
	const key = typeof secret === "string" ? decodeBase32(secret) : undefined;
	if (record === undefined || key === undefined) throw new Error("no TOTP factor was bound");
	return { id: record.id, key, binding: record.binding };
}

/** A login's first binding of TOTP, the proof given first when `sender` is handed. */
async function bindAtLogin(booted: Composed, sender?: RecordingMailSender) {
	const create = vi.spyOn(booted.userSessionStore, "create");
	const { agent, transaction, hints } = await beginFirstBinding(booted.app);
	expect(hints.email_proof).toBe(sender !== undefined);
	if (sender !== undefined) {
		const proved = await giveEmailProof(agent, transaction, sender);
		expect(proved.status, JSON.stringify(proved.body)).toBe(200);
	}
	const begun = await beginEnrollment(agent, transaction, "totp");
	expect(begun.status, JSON.stringify(begun.body)).toBe(200);
	const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
	const created = create.mock.calls.map(([record]) => record);
	create.mockRestore();
	return { agent, done, created, factor: await boundTotp(booted, begun.body.secret) };
}

/** The next password login, half a minute on, finished with the TOTP factor: the session it writes. */
async function nextSignIn(booted: Composed, factor: { readonly id: string; readonly key: Buffer }) {
	freezeClock(T0 + 30_000);
	const create = vi.spyOn(booted.userSessionStore, "create");
	const { agent, transaction } = await beginLogin(booted.app);
	const verified = await verify(agent, transaction, factor.id, totpCode(factor.key));
	expect(verified.status, JSON.stringify(verified.body)).toBe(200);
	expect(create).toHaveBeenCalledTimes(1);
	return create.mock.calls[0]?.[0];
}

describe("a login's first binding made without the account-email proof", () => {
	it.each(UNPROVEN)(
		"%s: answers the factor and its codes and establishes no session; the next sign-in with the factor records it",
		async (_label, setup) => {
			const booted = await composed(setup);

			const { agent, done, created, factor } = await bindAtLogin(booted);

			expect(done.status, JSON.stringify(done.body)).toBe(200);
			expect(done.body).toEqual({
				factor: { id: factor.id, kind: "totp" },
				recovery_codes: expect.any(Array),
			});
			expect(created).toEqual([]);
			expect(factor.binding).toBe("password");
			expect(booted.audit.of("mfa.factor.enrolled")).toEqual([
				expect.objectContaining({
					details: { kind: "totp", purpose: "login", binding: "password", by: "user" },
				}),
			]);
			// The browser holds no signed-in session: the account page sends it to log in.
			const account = await enrollFromAccount(agent, "totp");
			expect(account.status).toBe(401);
			expect(account.body).toEqual(LOGIN_REQUIRED);

			expect(await nextSignIn(booted, factor)).toMatchObject({
				sub: ALICE.id,
				amr: [PASSWORD_AMR, OTP_AMR, MFA_AMR],
				authentication: { primary: PASSWORD_AMR, mfaAt: new Date(T0 + 30_000) },
			});
		},
	);
});

describe("a login's first binding made with the account-email proof", () => {
	it("establishes the login with the factor at once: its amr and mfaAt", async () => {
		const booted = await composed();

		const { done, created, factor } = await bindAtLogin(
			booted,
			booted.sender as RecordingMailSender,
		);

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).toMatchObject({ message: "Logged in successfully" });
		expect(factor.binding).toBe("email_proof");
		expect(created).toEqual([
			expect.objectContaining({
				sub: ALICE.id,
				amr: [PASSWORD_AMR, OTP_AMR, MFA_AMR],
				authentication: { primary: PASSWORD_AMR, mfaAt: new Date(T0) },
			}),
		]);
	});
});

/** A revocation service whose every call reports every session and token ended. */
const revocationService = (): SubjectRevocationService => ({
	revokeAllForSubject: vi.fn(
		async (): Promise<SubjectRevocationReport> => ({
			sessionsRevoked: [],
			sessionsFailed: [],
			tokensRevoked: true,
			grantsRequested: false,
			grantsRevoked: [],
			grantsFailed: [],
			grantsRetired: [],
			grantsRetireFailed: [],
			unavailable: [],
			failures: [],
			complete: true,
			federationGrants: { requested: "revoke", applied: "revoke" },
		}),
	),
});

describe("the first binding after an operator reset", () => {
	/** Boots under `never` with the reset installed, alice holding a TOTP factor, and resets her as `requireEmailProof` says. */
	async function resetThenLogin(requireEmailProof: boolean) {
		const booted = await composed({
			requireEmailProof: "never",
			extraModules: [
				mfaResetModule,
				defineModule({
					name: "test:subject-revocation-service",
					provides: { subjectRevocationService: () => revocationService() } as never,
				}),
			],
		});
		await seedTotp(booted.factorStore);
		const { mfaReset } = booted.handle.components as unknown as {
			readonly mfaReset: ReturnType<typeof createMfaReset>;
		};
		const report = await mfaReset.resetMfaForSubject(ALICE.id, { requireEmailProof });
		expect(report.complete).toBe(true);
		return booted;
	}

	it("counts at once when the reset asked for the proof and it was given", async () => {
		const booted = await resetThenLogin(true);

		const { done, created, factor } = await bindAtLogin(
			booted,
			booted.sender as RecordingMailSender,
		);

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(factor.binding).toBe("email_proof");
		expect(created).toEqual([
			expect.objectContaining({
				amr: [PASSWORD_AMR, OTP_AMR, MFA_AMR],
				authentication: { primary: PASSWORD_AMR, mfaAt: new Date(T0) },
			}),
		]);
	});

	it("counts from the next sign-in when the reset asked for none and the setting asks for none", async () => {
		const booted = await resetThenLogin(false);

		const { done, created, factor } = await bindAtLogin(booted);

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body.message).toBeUndefined();
		expect(factor.binding).toBe("password");
		expect(created).toEqual([]);
		expect(await nextSignIn(booted, factor)).toMatchObject({
			amr: [PASSWORD_AMR, OTP_AMR, MFA_AMR],
			authentication: { primary: PASSWORD_AMR, mfaAt: new Date(T0 + 30_000) },
		});
	});
});

describe("a first binding from the account page", () => {
	it.each(UNPROVEN)(
		"%s: leaves the session as it was — no second factor recorded, its express id kept — and the session then steps up with the factor it bound",
		async (_label, setup) => {
			const booted = await composed({ ...setup, mode: "optional" });
			const { agent, sid } = await signIn(booted.app, booted.userSessionStore);
			const before = await booted.userSessionStore.get(sid);

			const begun = await enrollFromAccount(agent, "totp");
			expect(begun.status, JSON.stringify(begun.body)).toBe(200);
			const done = await completeEnrollment(
				agent,
				begun.body.transaction as string,
				totpProofOf(begun.body.secret),
			);

			expect(done.status, JSON.stringify(done.body)).toBe(200);
			expect(done.body).toEqual({
				factor: { id: expect.any(String), kind: "totp" },
				recovery_codes: expect.any(Array),
			});
			const factor = await boundTotp(booted, begun.body.secret);
			expect(factor.binding).toBe("password");
			expect(sessionIdSet(done)).toBeUndefined();
			expect(await booted.userSessionStore.get(sid)).toEqual(before);
			expect(before?.authentication?.mfaAt).toBeUndefined();

			freezeClock(T0 + 30_000);
			const opened = await stepUp(agent);
			expect(opened.status, JSON.stringify(opened.body)).toBe(200);
			const stepped = await verify(
				agent,
				opened.body.transaction as string,
				factor.id,
				totpCode(factor.key),
			);
			expect(stepped.status, JSON.stringify(stepped.body)).toBe(200);
			expect(stepped.body).toEqual({ step_up: "verified" });
			expect(await booted.userSessionStore.get(sid)).toMatchObject({
				amr: [PASSWORD_AMR, OTP_AMR, MFA_AMR],
				authentication: { primary: PASSWORD_AMR, mfaAt: new Date(T0 + 30_000) },
			});
		},
	);

	it("escalates the session when the account-email proof was given there", async () => {
		const booted = await composed({ mode: "optional" });
		const { agent, sid } = await signIn(booted.app, booted.userSessionStore);
		const opened = await stepUp(agent);
		expect(opened.status, JSON.stringify(opened.body)).toBe(200);
		const proved = await giveEmailProof(
			agent,
			opened.body.transaction as string,
			booted.sender as RecordingMailSender,
		);
		expect(proved.status, JSON.stringify(proved.body)).toBe(200);

		const begun = await enrollFromAccount(agent, "totp");
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const done = await completeEnrollment(
			agent,
			begun.body.transaction as string,
			totpProofOf(begun.body.secret),
		);

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect((await boundTotp(booted, begun.body.secret)).binding).toBe("email_proof");
		expect(sessionIdSet(done)).toBeDefined();
		expect(await booted.userSessionStore.get(sid)).toMatchObject({
			amr: [PASSWORD_AMR, OTP_AMR, MFA_AMR],
			authentication: { primary: PASSWORD_AMR, mfaAt: new Date(T0) },
		});
	});
});
