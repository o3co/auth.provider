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
 * The account-email proof before a login's first binding (the MFA ADR's
 * D24, D25, F3 step 2, D21's 80-bit row), through the composed application:
 * with a mail sender and an address, `mfa.enrollment.requireEmailProof =
 * "when-mail"` asks for it; `POST /session/mfa/challenge` with `factor_id:
 * "account-email"` mails a long code to the login's address and answers
 * where it went, masked; `POST /session/mfa/verify` takes it, limited by the
 * transaction and never by the subject lock; the binding then records
 * `email_proof`. `always`, `never`, no sender, no address and D25's flag,
 * and the boot rules.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaTransactionStore,
} from "@o3co/auth-provider-core";
import {
	createRecordingMailSender,
	type RecordingMailSender,
} from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatLongCode } from "#/codes.mjs";
import {
	ALICE,
	boot,
	configFor,
	directoryEntries,
	disposeAll,
	events,
	refusal,
	WitnessingUserRepository,
} from "./moduleHarness.mjs";
import {
	beginEnrollment,
	beginFirstBinding,
	completeEnrollment,
	freezeClock,
	loggedText,
	mfaPost,
	readTransaction,
	recordingAuditSink,
	T0,
	thawClock,
	totpProofOf,
	verify,
} from "./routesHarness.mjs";

beforeEach(() => freezeClock());
afterEach(async () => {
	await disposeAll();
	thawClock();
});

const ACCOUNT_EMAIL = "account-email";
const PROOF_REQUIRED = {
	error: "mfa_email_proof_required",
	error_description: "The account-email proof comes first",
};
const PROOF_UNAVAILABLE = {
	error: "mfa_email_proof_unavailable",
	error_description: "The account-email proof cannot be given for this account",
};

/** The directory, alice's address taken away when `withoutAddress`. */
function directory(withoutAddress = false): WitnessingUserRepository {
	const entries = directoryEntries();
	if (withoutAddress) delete entries.get(ALICE.username)?.email;
	return new WitnessingUserRepository(entries);
}

/** Boots `mode` with a recording sender (unless `sender` is `null`) and `requireEmailProof`. */
async function withMail(
	options: {
		readonly sender?: RecordingMailSender | null;
		readonly requireEmailProof?: "when-mail" | "always" | "never";
		readonly withoutAddress?: boolean;
		readonly transactionStore?: MfaTransactionStore;
	} = {},
) {
	const sender = options.sender === undefined ? createRecordingMailSender() : options.sender;
	const factorStore = createMemoryMfaFactorStore();
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor("required", {
			enrollment: { requireEmailProof: options.requireEmailProof ?? "when-mail" },
		}),
		factorStore,
		auditSink: audit,
		userRepository: directory(options.withoutAddress),
		...(options.transactionStore === undefined
			? {}
			: { transactionStore: options.transactionStore }),
		...(sender === null ? {} : { mailSender: sender }),
	});
	return { ...booted, sender, audit };
}

const challengeProof = (agent: Parameters<typeof mfaPost>[0], transaction: string) =>
	mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: ACCOUNT_EMAIL });

/** The code the sender was handed last. */
const lastCode = (sender: RecordingMailSender | null): string => {
	const code = sender?.sent.at(-1)?.code;
	if (code === undefined) throw new Error("nothing was sent");
	return code;
};

describe("a first binding where mail is wired and the account has an address", () => {
	it("asks for the proof first: the login's hint, the transaction's view, and no binding until it is given", async () => {
		const { app, transactionStore } = await withMail();
		const { agent, transaction, hints } = await beginFirstBinding(app);

		expect(hints).toEqual({ enrollable: ["totp"], email_proof: true });
		expect((await transactionStore.get(transaction))?.emailProof).toBe("required");
		expect((await readTransaction(agent, transaction)).body).toMatchObject({ email_proof: true });

		const begun = await beginEnrollment(agent, transaction, "totp");
		expect(begun.status).toBe(403);
		expect(begun.body).toEqual(PROOF_REQUIRED);
		const completed = await completeEnrollment(agent, transaction, "123456");
		expect(completed.status).toBe(403);
		expect(completed.body).toEqual(PROOF_REQUIRED);
		expect((await transactionStore.get(transaction))?.pendingEnrollment).toBeUndefined();
	});

	it("mails a long code to the login's address, answering where it went, masked, and how long it stands", async () => {
		const { app, sender, audit, transactionStore, logger } = await withMail();
		const { agent, transaction } = await beginFirstBinding(app);

		const res = await challengeProof(agent, transaction);

		expect(res.status).toBe(200);
		expect(res.headers["cache-control"]).toBe("no-store");
		expect(res.body).toEqual({ sent_to: "a***@example.com", expires_in: 600 });
		expect(sender?.sent).toEqual([
			{
				purpose: "account_email_proof",
				subject: ALICE.id,
				to: ALICE.email,
				code: expect.stringMatching(/^[0-9A-HJKMNP-TV-Z]{16}$/),
				expiresAtMs: T0 + 600_000,
			},
		]);
		const kept = await transactionStore.get(transaction);
		expect(kept?.challenge).toMatchObject({ factorId: ACCOUNT_EMAIL, kind: ACCOUNT_EMAIL });
		expect(kept?.challenge?.state).not.toContain(lastCode(sender));
		expect(audit.of("mfa.challenge.sent")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: ACCOUNT_EMAIL, purpose: "login" },
			}),
		]);
		expect(loggedText(logger)).not.toContain(lastCode(sender));
		expect(loggedText(logger)).not.toContain(ALICE.email);
		expect(JSON.stringify(audit.events)).not.toContain(ALICE.email);
	});

	it("takes the code as it was shown, in either case, then binds with the proof recorded: binding email_proof on the factor and the codes", async () => {
		const { app, sender, audit, transactionStore, factorStore } = await withMail();
		const { agent, transaction } = await beginFirstBinding(app);
		await challengeProof(agent, transaction);

		const proved = await verify(
			agent,
			transaction,
			ACCOUNT_EMAIL,
			formatLongCode(lastCode(sender)).toLowerCase(),
		);

		expect(proved.status).toBe(200);
		expect(proved.body).toEqual({ email_proof: "verified" });
		expect(await transactionStore.get(transaction)).toMatchObject({
			emailProof: { provedAtMs: T0 },
			challenge: undefined,
		});
		expect((await readTransaction(agent, transaction)).body).toMatchObject({ email_proof: false });
		expect(audit.of("mfa.verified")).toEqual([
			expect.objectContaining({ details: { kind: ACCOUNT_EMAIL, purpose: "login" } }),
		]);

		const begun = await beginEnrollment(agent, transaction, "totp");
		expect(begun.status).toBe(200);
		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));
		expect(done.status).toBe(200);
		expect(
			(await factorStore.list(ALICE.id)).map((record) => [record.kind, record.binding]).sort(),
		).toEqual([
			["recovery_code", "email_proof"],
			["totp", "email_proof"],
		]);
		expect(audit.of("mfa.factor.enrolled")[0]?.details).toMatchObject({ binding: "email_proof" });
	});

	it("ends the transaction after five wrong proofs without touching the subject lock", async () => {
		const store = createMemoryMfaTransactionStore();
		const reserveSubjectAttempt = vi.fn(store.reserveSubjectAttempt);
		const { app, audit, transactionStore } = await withMail({
			transactionStore: { ...store, reserveSubjectAttempt },
		});
		const { agent, transaction } = await beginFirstBinding(app);
		await challengeProof(agent, transaction);

		const remaining: unknown[] = [];
		for (let attempt = 1; attempt <= 6; attempt++) {
			const res = await verify(agent, transaction, ACCOUNT_EMAIL, "0000-0000-0000-0000");
			expect(res.status, String(attempt)).toBe(401);
			remaining.push(res.body.attempts_remaining);
		}

		expect(remaining).toEqual([4, 3, 2, 1, 0, 0]);
		expect(await transactionStore.get(transaction)).toBeNull();
		expect((await verify(agent, transaction, ACCOUNT_EMAIL, "0000")).status).toBe(400);
		expect(reserveSubjectAttempt).not.toHaveBeenCalled();
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"invalid",
			"invalid",
			"invalid",
			"invalid",
			"invalid",
			"exhausted",
		]);
	});

	it("keeps the code across attempts, and a resend replaces it", async () => {
		const { app, sender } = await withMail();
		const { agent, transaction } = await beginFirstBinding(app);
		await challengeProof(agent, transaction);
		const first = lastCode(sender);

		expect((await verify(agent, transaction, ACCOUNT_EMAIL, "not-a-code")).status).toBe(401);
		await challengeProof(agent, transaction);
		const second = lastCode(sender);
		expect(second).not.toBe(first);
		expect((await verify(agent, transaction, ACCOUNT_EMAIL, first)).status).toBe(401);
		expect((await verify(agent, transaction, ACCOUNT_EMAIL, second)).status).toBe(200);
	});

	it("answers a proof the transaction does not ask for as an unknown factor, sending nothing", async () => {
		const { app, sender } = await withMail({ requireEmailProof: "never" });
		const { agent, transaction, hints } = await beginFirstBinding(app);
		expect(hints.email_proof).toBe(false);

		const res = await challengeProof(agent, transaction);

		expect(res.status).toBe(400);
		expect(res.body.error_description).toBe("Unknown second factor");
		expect((await verify(agent, transaction, ACCOUNT_EMAIL, "0000")).status).toBe(400);
		expect(sender?.sent).toEqual([]);
	});

	it("answers a sender's outage 503 once — mfa_mail_unavailable for the proof — keeping the transaction", async () => {
		const sender = createRecordingMailSender();
		sender.failWith(new Error("relay down"));
		const { app, logger, transactionStore } = await withMail({ sender });
		const { agent, transaction } = await beginFirstBinding(app);

		const res = await challengeProof(agent, transaction);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_mail_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "challenge",
			purpose: "account_email_proof",
			kind: ACCOUNT_EMAIL,
			reason: "outage",
		});
		expect(await transactionStore.get(transaction)).toMatchObject({ challenge: undefined });
	});
});

describe("a first binding where the proof is not asked", () => {
	it("asks for none without a mail sender, as before: the binding proceeds, recorded password", async () => {
		const { app, factorStore } = await withMail({ sender: null });
		const { agent, transaction, hints } = await beginFirstBinding(app);
		expect(hints.email_proof).toBe(false);

		const begun = await beginEnrollment(agent, transaction, "totp");
		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(200);
		expect(
			(await factorStore.list(ALICE.id)).every((record) => record.binding === "password"),
		).toBe(true);
	});

	it("asks for none under when-mail for an account without an address", async () => {
		const { app } = await withMail({ withoutAddress: true });
		const { agent, transaction, hints } = await beginFirstBinding(app);
		expect(hints.email_proof).toBe(false);
		expect((await beginEnrollment(agent, transaction, "totp")).status).toBe(200);
	});
});

describe("a proof nobody can give", () => {
	it("under always, for an account without an address: asked, refused 403 at the proof and at the binding, never skipped", async () => {
		const { app, sender } = await withMail({ requireEmailProof: "always", withoutAddress: true });
		const { agent, transaction, hints } = await beginFirstBinding(app);
		expect(hints.email_proof).toBe(true);

		const res = await challengeProof(agent, transaction);
		expect(res.status).toBe(403);
		expect(res.body).toEqual(PROOF_UNAVAILABLE);
		expect(sender?.sent).toEqual([]);
		expect((await beginEnrollment(agent, transaction, "totp")).body).toEqual(PROOF_REQUIRED);
	});

	it("while D25's flag stands without a mail sender: asked, refused 403 at the proof", async () => {
		const store = createMemoryMfaTransactionStore();
		await store.requireEmailProofAtNextBinding(ALICE.id);
		const { app } = await withMail({
			sender: null,
			transactionStore: store,
			requireEmailProof: "never",
		});
		const { agent, transaction, hints } = await beginFirstBinding(app);
		expect(hints.email_proof).toBe(true);

		const res = await challengeProof(agent, transaction);
		expect(res.status).toBe(403);
		expect(res.body).toEqual(PROOF_UNAVAILABLE);
	});
});

describe("D25's flag", () => {
	it("asks for the proof whatever the setting, and is consumed once the first counting factor is written", async () => {
		const store = createMemoryMfaTransactionStore();
		await store.requireEmailProofAtNextBinding(ALICE.id);
		const { app, sender } = await withMail({ transactionStore: store, requireEmailProof: "never" });
		const { agent, transaction, hints } = await beginFirstBinding(app);
		expect(hints.email_proof).toBe(true);

		await challengeProof(agent, transaction);
		expect((await verify(agent, transaction, ACCOUNT_EMAIL, lastCode(sender))).status).toBe(200);
		const begun = await beginEnrollment(agent, transaction, "totp");
		expect(await store.emailProofRequiredAtNextBinding(ALICE.id)).toBe(true);
		const done = await completeEnrollment(agent, transaction, totpProofOf(begun.body.secret));

		expect(done.status).toBe(200);
		expect(await store.emailProofRequiredAtNextBinding(ALICE.id)).toBe(false);
	});

	it("stands when the binding fails before the factor is written", async () => {
		const store = createMemoryMfaTransactionStore();
		await store.requireEmailProofAtNextBinding(ALICE.id);
		const { app, sender } = await withMail({ transactionStore: store });
		const { agent, transaction } = await beginFirstBinding(app);
		await challengeProof(agent, transaction);
		await verify(agent, transaction, ACCOUNT_EMAIL, lastCode(sender));
		await beginEnrollment(agent, transaction, "totp");

		expect((await completeEnrollment(agent, transaction, "000000")).status).toBe(401);
		expect(await store.emailProofRequiredAtNextBinding(ALICE.id)).toBe(true);
	});
});

describe("the boot rules", () => {
	it('refuses requireEmailProof = "always" without a mail sender: nobody could give the proof, so nobody could bind', async () => {
		const err = await refusal({
			config: configFor("required", { enrollment: { requireEmailProof: "always" } }),
		});
		expect(err.reason).toBe("contribute-factory-failed");
		const message = (err.cause as Error).message;
		expect(message).toContain("mfa.enrollment.requireEmailProof");
		expect(message).toContain("mail sender");
		expect(message).toContain("MFA_ENROLLMENT_REQUIRE_EMAIL_PROOF");
	});

	it("says once at boot that when-mail binds without the proof when no mail sender is wired", async () => {
		const { logger } = await boot({ config: configFor("required") });
		const said = logger.warn.mock.calls.filter(
			(call) => call[1] === "mfa_first_binding_without_email_proof",
		);
		expect(said).toEqual([
			[
				{ setting: "mfa.enrollment.requireEmailProof", value: "when-mail" },
				"mfa_first_binding_without_email_proof",
			],
		]);
	});

	it("says nothing with a mail sender, or under never", async () => {
		const wired = await boot({
			config: configFor("required"),
			mailSender: createRecordingMailSender(),
		});
		expect(events(wired.logger, "warn")).not.toContain("mfa_first_binding_without_email_proof");
		const never = await boot({
			config: configFor("required", { enrollment: { requireEmailProof: "never" } }),
		});
		expect(events(never.logger, "warn")).not.toContain("mfa_first_binding_without_email_proof");
	});
});
