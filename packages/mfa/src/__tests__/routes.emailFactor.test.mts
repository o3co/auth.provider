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
 * The email factor through the composed application (the MFA ADR's F5, D5,
 * D11, D14, D21, D23): its module switched on beside a mail sender, a
 * six-digit login code mailed at each challenge to the login's address while
 * it matches the digest the factor recorded, a long enrollment code mailed to
 * the account's address alone, the subject lock on its codes, and the
 * answers a page reads — the masked address and the code's life.
 */

import { randomBytes } from "node:crypto";
import {
	type AppConfig,
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	createRecordingMailSender,
	type RecordingMailSender,
} from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRecoveryCodeFactor, generateRecoveryCodes } from "#/recovery/factor.mjs";
import {
	mfaEmailFactorConfigForTests,
	mfaRecoveryCodeFactorConfigForTests,
	openMfaFactorDataForTests,
} from "#/testing/index.mjs";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	MFA_KEY,
	refusal,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	type Agent,
	beginFirstBinding,
	beginLogin,
	completeEnrollment,
	enrollFromAccount,
	freezeClock,
	giveEmailProof,
	loggedText,
	mfaPost,
	recordingAuditSink,
	seedFactor,
	seedTotp,
	signInWithTotp,
	suiteSealing,
	T0,
	thawClock,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const KIND = "email";
const SENT_TO = "a***@example.com";
const SIX_DIGITS = /^[0-9]{6}$/;
const FACTOR_REFUSED = {
	error: "mfa_factor_refused",
	error_description: "This second factor cannot be used: use another",
};

/** The digest the email factor records for `address`, under the suite's ring. */
const recordedDigest = (address: string) => suiteSealing().digestsFor(KIND).digest([address]);

interface Setup {
	readonly mode?: "optional" | "required";
	readonly addsMfa?: boolean;
	readonly codeTtlSeconds?: number;
	readonly totp?: boolean;
	readonly recovery?: boolean;
	readonly mfa?: Record<string, unknown>;
	readonly sender?: RecordingMailSender;
	readonly factorStore?: MfaFactorStore;
	readonly users?: WitnessingUserRepository;
}

/** The composition's configuration: the email factor on, TOTP and recovery codes as `setup` says. */
const configOf = (setup: Setup): AppConfig =>
	({
		...configFor(setup.mode ?? "required", setup.mfa ?? {}, { enabled: setup.totp ?? false }),
		...mfaRecoveryCodeFactorConfigForTests({ enabled: setup.recovery ?? true }),
		...mfaEmailFactorConfigForTests({
			enabled: true,
			addsMfa: setup.addsMfa ?? false,
			...(setup.codeTtlSeconds === undefined ? {} : { codeTtlSeconds: setup.codeTtlSeconds }),
		}),
	}) as AppConfig;

/** Boots the email factor on with a recording sender and an audit sink. */
async function composed(setup: Setup = {}) {
	const factorStore = setup.factorStore ?? createMemoryMfaFactorStore();
	const transactionStore = createMemoryMfaTransactionStore();
	const sender = setup.sender ?? createRecordingMailSender();
	const audit = recordingAuditSink();
	const config = configOf(setup);
	const booted = await boot({
		config,
		factorStore,
		transactionStore,
		auditSink: audit,
		mailSender: sender,
		...(setup.users === undefined ? {} : { userRepository: setup.users }),
	});
	return { ...booted, config, factorStore, transactionStore, sender, audit };
}

/** Boots with alice holding an email factor that recorded `data` (her address's digest unless given). */
async function withEmailFactor(setup: Setup & { readonly data?: Record<string, unknown> } = {}) {
	const factorStore = setup.factorStore ?? createMemoryMfaFactorStore();
	const record = await seedFactor(
		factorStore,
		KIND,
		setup.data ?? { addressDigest: recordedDigest(ALICE.email) },
	);
	return { ...(await composed({ ...setup, factorStore })), record };
}

const challenge = (agent: Agent, transaction: string, factorId: string) =>
	mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: factorId });

/** The code the sender was handed last. */
const lastCode = (sender: RecordingMailSender): string => {
	const code = sender.sent.at(-1)?.code;
	if (code === undefined) throw new Error("nothing was sent");
	return code;
};

/** A six-digit code that is not `code`. */
const otherThan = (code: string): string => String((Number(code) + 1) % 1_000_000).padStart(6, "0");

describe("a login with the email factor", () => {
	it("mails a six-digit code to the login's address, answers the masked address and the code's life, and the code completes the login with email, not mfa", async () => {
		const { app, record, sender, audit, userSessionStore } = await withEmailFactor();
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ sent_to: SENT_TO, expires_in: 600 });
		expect(sender.sent).toEqual([
			{
				purpose: "login_code",
				subject: ALICE.id,
				to: ALICE.email,
				code: expect.stringMatching(SIX_DIGITS),
				expiresAtMs: T0 + 600_000,
			},
		]);
		expect(audit.of("mfa.challenge.sent")).toEqual([
			expect.objectContaining({ details: { kind: KIND, purpose: "login" } }),
		]);

		const done = await verify(agent, transaction, record.id, lastCode(sender));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(create.mock.calls[0]?.[0]).toMatchObject({
			sub: ALICE.id,
			amr: ["pwd", "email"],
			authentication: { primary: "pwd", mfaAt: new Date(T0) },
		});
	});

	it("adds mfa when its section says so", async () => {
		const { app, record, sender, userSessionStore } = await withEmailFactor({ addsMfa: true });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { agent, transaction } = await beginLogin(app);
		await challenge(agent, transaction, record.id);

		expect((await verify(agent, transaction, record.id, lastCode(sender))).status).toBe(200);
		expect(create.mock.calls[0]?.[0]).toMatchObject({ amr: ["pwd", "email", "mfa"] });
	});

	it("gives a code mfa-email-factor.codeTtlSeconds, capped at the transaction's expiry", async () => {
		const short = await withEmailFactor({ codeTtlSeconds: 120 });
		const first = await beginLogin(short.app);
		expect((await challenge(first.agent, first.transaction, short.record.id)).body).toEqual({
			sent_to: SENT_TO,
			expires_in: 120,
		});
		expect(short.sender.sent.at(-1)?.expiresAtMs).toBe(T0 + 120_000);
		await disposeAll();

		const capped = await withEmailFactor({ mfa: { transactionTtlSeconds: 60 } });
		const second = await beginLogin(capped.app);
		expect((await challenge(second.agent, second.transaction, capped.record.id)).body).toEqual({
			sent_to: SENT_TO,
			expires_in: 60,
		});
		expect(capped.sender.sent.at(-1)?.expiresAtMs).toBe(T0 + 60_000);
	});

	it("keeps the code across a wrong attempt, and a resend refuses the earlier code while the latest verifies", async () => {
		const { app, record, sender } = await withEmailFactor();
		const { agent, transaction } = await beginLogin(app);
		await challenge(agent, transaction, record.id);
		const earlier = lastCode(sender);

		const wrong = await verify(agent, transaction, record.id, otherThan(earlier));
		expect(wrong.status).toBe(401);
		expect(wrong.body).toMatchObject({ error: "mfa_invalid", attempts_remaining: 4 });

		await challenge(agent, transaction, record.id);
		const latest = lastCode(sender);
		expect(sender.sent).toHaveLength(2);
		if (latest !== earlier) {
			const stale = await verify(agent, transaction, record.id, earlier);
			expect(stale.status).toBe(401);
		}
		expect((await verify(agent, transaction, record.id, latest)).status).toBe(200);
	});

	it("never mails a code anywhere but the login's address: an address in the request is not read", async () => {
		const { app, record, sender } = await withEmailFactor();
		const { agent, transaction } = await beginLogin(app);

		const res = await mfaPost(agent, "/challenge", {
			transaction_id: transaction,
			factor_id: record.id,
			email: "attacker@example.net",
			to: "attacker@example.net",
		});

		expect(res.status).toBe(200);
		expect(sender.sent.map((mail) => mail.to)).toEqual([ALICE.email]);
	});

	it("is refused once the account's address no longer matches the one it recorded: 403, mfa.email_address_mismatch, nothing sent or kept", async () => {
		const { app, record, sender, audit, transactionStore } = await withEmailFactor({
			data: { addressDigest: recordedDigest("old@example.com") },
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(403);
		expect(res.body).toEqual(FACTOR_REFUSED);
		expect(sender.sent).toEqual([]);
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
		expect(audit.of("mfa.email_address_mismatch")).toEqual([
			expect.objectContaining({ subject: ALICE.id, details: { kind: KIND, purpose: "login" } }),
		]);
	});

	it("is answered 503 when the sender fails — the code cleared, the transaction standing — and 429 at the sender's limit; the page asks again", async () => {
		const sender = createRecordingMailSender();
		const { app, record, transactionStore } = await withEmailFactor({ sender });
		const { agent, transaction } = await beginLogin(app);

		sender.failWith(new Error("relay down"));
		const failed = await challenge(agent, transaction, record.id);
		expect(failed.status).toBe(503);
		expect(await transactionStore.get(transaction)).toMatchObject({ challenge: undefined });

		sender.refuseAtLimit();
		const limited = await challenge(agent, transaction, record.id);
		expect(limited.status).toBe(429);
		expect(limited.body.error).toBe("rate_limited");
		expect(await transactionStore.get(transaction)).toMatchObject({ challenge: undefined });

		sender.recover();
		expect((await challenge(agent, transaction, record.id)).status).toBe(200);
		expect((await verify(agent, transaction, record.id, lastCode(sender))).status).toBe(200);
	});

	it("is answered 503 mfa_factor_unreadable when its recorded digest names a key the ring no longer holds, sending nothing", async () => {
		const { app, record, sender, logger } = await withEmailFactor({
			data: { addressDigest: { ...recordedDigest(ALICE.email), keyId: "k-gone" } },
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect(sender.sent).toEqual([]);
	});

	it("records its digest again under the ring's first key at a login, once the ring was rotated", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const recorded = recordedDigest(ALICE.email);
		const record = await seedFactor(factorStore, KIND, { addressDigest: recorded });
		const rotated = {
			encryptionKeys: [{ key: randomBytes(32).toString("base64") }, { key: MFA_KEY }],
		};
		const { app, sender, config } = await composed({ factorStore, mfa: rotated });
		const { agent, transaction } = await beginLogin(app);
		await challenge(agent, transaction, record.id);

		expect((await verify(agent, transaction, record.id, lastCode(sender))).status).toBe(200);

		const stored = (await factorStore.list(ALICE.id)).find((entry) => entry.id === record.id);
		if (stored === undefined) throw new Error("the factor is gone");
		const data = openMfaFactorDataForTests(config, stored);
		const now = data.addressDigest as { keyId: string; digest: string };
		expect(now.keyId).not.toBe(recorded.keyId);
		expect(Object.keys(data)).toEqual(["addressDigest"]);
	});

	it("writes neither the code nor the address into a log line or an audit event", async () => {
		const sender = createRecordingMailSender();
		const { app, record, logger, audit } = await withEmailFactor({ sender });
		const { agent, transaction } = await beginLogin(app);
		await challenge(agent, transaction, record.id);
		const first = lastCode(sender);
		await verify(agent, transaction, record.id, otherThan(first));
		sender.failWith(new Error(`relay refused ${ALICE.email}`));
		await challenge(agent, transaction, record.id);
		const failedCode = lastCode(sender);
		sender.recover();
		await challenge(agent, transaction, record.id);
		const last = lastCode(sender);
		await verify(agent, transaction, record.id, last);

		const logged = loggedText(logger);
		const audited = JSON.stringify(audit.events);
		for (const secret of [ALICE.email, first, failedCode, last]) {
			expect(logged).not.toContain(secret);
			expect(audited).not.toContain(secret);
		}
	});
});

describe("the email factor's codes under the subject lock", () => {
	it("spends one of the subject's attempts per wrong code, holds the right code at verification with the kinds still usable, and still mails a code while held", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const set = generateRecoveryCodes(
			createRecoveryCodeFactor({ count: 3 }),
			suiteSealing().digestsFor("recovery_code"),
		);
		if (set === undefined) throw new Error("no set");
		await seedFactor(factorStore, "recovery_code", set.data);
		const { app, record, sender } = await withEmailFactor({
			factorStore,
			mfa: { lockout: { threshold: 2 } },
		});
		const { agent, transaction } = await beginLogin(app);
		await challenge(agent, transaction, record.id);
		const code = lastCode(sender);
		for (const remaining of [4, 3]) {
			const res = await verify(agent, transaction, record.id, otherThan(code));
			expect(res.status).toBe(401);
			expect(res.body.attempts_remaining).toBe(remaining);
		}

		const held = await verify(agent, transaction, record.id, code);

		expect(held.status, JSON.stringify(held.body)).toBe(429);
		expect(held.body).toMatchObject({
			error: "mfa_locked",
			hold: "backoff",
			usable_kinds: ["recovery_code"],
		});

		const again = await challenge(agent, transaction, record.id);
		expect(again.status).toBe(200);
		expect(sender.sent).toHaveLength(2);
	});
});

describe("enrolling the email factor", () => {
	it("at a login's first binding: the account-email proof, then a long code to the account's address alone, the page answered the masked address and the code's life, and the record keeping only its address digest", async () => {
		const { app, sender, factorStore } = await composed();
		const { agent, transaction, hints } = await beginFirstBinding(app);
		expect(hints).toEqual({ enrollable: ["email"], email_proof: true });
		expect((await giveEmailProof(agent, transaction, sender)).status).toBe(200);

		const begun = await mfaPost(agent, "/enrollment", {
			transaction_id: transaction,
			kind: KIND,
			email: "attacker@example.net",
		});

		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		expect(begun.body).toEqual({ sent_to: SENT_TO, expires_in: 600 });
		expect(sender.sent.map(({ purpose, to }) => ({ purpose, to }))).toEqual([
			{ purpose: "account_email_proof", to: ALICE.email },
			{ purpose: "email_factor_enrollment", to: ALICE.email },
		]);

		const done = await completeEnrollment(agent, transaction, lastCode(sender));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).toMatchObject({
			message: "Logged in successfully",
			factor: { kind: KIND },
			recovery_codes: expect.any(Array),
		});
		const email = (await factorStore.list(ALICE.id)).find((entry) => entry.kind === KIND);
		expect(email?.binding).toBe("email_proof");
		if (email === undefined) return;
		const opened = suiteSealing().openFactorData(email, email.data);
		expect(opened).toEqual({
			state: "ok",
			value: { addressDigest: recordedDigest(ALICE.email) },
		});
	});

	it("refuses the earlier enrollment code once another was mailed, and completes with the latest", async () => {
		const { app, sender } = await composed();
		const { agent, transaction } = await beginFirstBinding(app);
		await giveEmailProof(agent, transaction, sender);
		await mfaPost(agent, "/enrollment", { transaction_id: transaction, kind: KIND });
		const earlier = lastCode(sender);
		await mfaPost(agent, "/enrollment", { transaction_id: transaction, kind: KIND });
		const latest = lastCode(sender);

		const stale = await completeEnrollment(agent, transaction, earlier);
		expect(stale.status).toBe(401);
		expect((await completeEnrollment(agent, transaction, latest)).status).toBe(200);
	});

	it("from the account page beside a TOTP factor: the code mailed to the account's address, its life answered with the transaction, bound by mfa", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const seeded = await seedTotp(factorStore);
		const { app, sender, userSessionStore } = await composed({ factorStore, totp: true });
		const { agent } = await signInWithTotp(app, userSessionStore as UserSessionStore, seeded);

		const begun = await enrollFromAccount(agent, KIND);

		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		expect(begun.body).toEqual({
			sent_to: SENT_TO,
			expires_in: 600,
			transaction: expect.any(String),
		});
		expect(sender.sent.at(-1)).toMatchObject({
			purpose: "email_factor_enrollment",
			to: ALICE.email,
		});

		const done = await completeEnrollment(agent, begun.body.transaction, lastCode(sender));

		expect(done.status, JSON.stringify(done.body)).toBe(200);
		expect(done.body).toEqual({ factor: { id: expect.any(String), kind: KIND } });
		const email = (await factorStore.list(ALICE.id)).find((entry) => entry.kind === KIND);
		expect(email?.binding).toBe("mfa");
	});

	it("answers a session's start with the code's life, not a longer transaction's", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const seeded = await seedTotp(factorStore);
		const { app, userSessionStore } = await composed({
			factorStore,
			totp: true,
			codeTtlSeconds: 120,
		});
		const { agent } = await signInWithTotp(app, userSessionStore as UserSessionStore, seeded);

		const begun = await enrollFromAccount(agent, KIND);

		expect(begun.body).toMatchObject({ sent_to: SENT_TO, expires_in: 120 });
	});

	it("refuses a second email factor for the same address as a duplicate", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const seeded = await seedTotp(factorStore);
		await seedFactor(factorStore, KIND, { addressDigest: recordedDigest(ALICE.email) });
		const { app, sender, userSessionStore } = await composed({ factorStore, totp: true });
		const { agent } = await signInWithTotp(app, userSessionStore as UserSessionStore, seeded);
		const begun = await enrollFromAccount(agent, KIND);

		const done = await completeEnrollment(agent, begun.body.transaction, lastCode(sender));

		expect(done.status).toBe(401);
		expect((await factorStore.list(ALICE.id)).filter((entry) => entry.kind === KIND)).toHaveLength(
			1,
		);
	});

	it("is not offered to an account without an address", async () => {
		const entries = directoryEntries();
		const alice = entries.get(ALICE.username);
		if (alice !== undefined) delete alice.email;
		const { app } = await composed({ totp: true, users: new WitnessingUserRepository(entries) });

		const { hints } = await beginFirstBinding(app);

		expect(hints.enrollable).toEqual(["totp"]);
	});
});

describe("the email factor's module in a composition", () => {
	it("refuses the boot when switched on with no mail sender wired, naming the switch and the slot", async () => {
		const err = await refusal({ config: configOf({}) });

		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toContain("mfa-email-factor.enabled");
		expect(err.message).toContain("MFA_EMAIL_FACTOR_ENABLED");
		expect(err.message).toContain("mailSender");
	});

	it("reaches email alone without addsMfa, so urn:o3co:acr:mfa is out of its reach; with addsMfa, mfa too", async () => {
		for (const [addsMfa, reach] of [
			[false, ["email"]],
			[true, ["email", "mfa"]],
		] as const) {
			const { handle } = await composed({ addsMfa, totp: false, recovery: false });
			expect(
				[...(handle.components.sessionRequirementResolver?.get("mfa")?.reach ?? [])].sort(),
			).toEqual(reach);
			await disposeAll();
		}
	});
});
