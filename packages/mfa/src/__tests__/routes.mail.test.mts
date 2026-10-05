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
 * A factor's login code mailed through `POST /session/mfa/challenge`, over
 * core's mailing factor double and recording sender (the MFA ADR's D5, F5 and
 * D23, as #810 amended them): the login's address is compared with the
 * digest the factor recorded before anything is written, the code is kept
 * with the digest of the address it went to and handed back to the
 * verification, the page is answered where the code went (masked) and how
 * long it lives, and what the sender answered decides the answer.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactor,
	type MfaTransactionStore,
	type MfaVerifyContext,
} from "@o3co/auth-provider-core";
import {
	createRecordingMailSender,
	createTestMfaFactor,
	type RecordingMailSender,
} from "@o3co/auth-provider-core/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ALICE, boot, configFor, disposeAll, events } from "./moduleHarness.mjs";
import {
	beginEnrollment,
	beginFirstBinding,
	beginLogin,
	contributing,
	freezeClock,
	loggedText,
	mfaPost,
	recordingAuditSink,
	seedFactor,
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

const KIND = "mailed";

/** The digest the factor records for `address`, under the suite's ring, as its enrollment's completion is handed it. */
const recordedDigest = (address: string) => suiteSealing().digestsFor(KIND).digest([address]);

/** Core's mailing factor double under {@link KIND}, its verification watched. */
function mailed(): { readonly factor: MfaFactor; readonly verified: MfaVerifyContext[] } {
	const double = createTestMfaFactor({ kind: KIND, mail: true });
	const verified: MfaVerifyContext[] = [];
	return {
		verified,
		factor: {
			...double,
			verify: async (ctx) => {
				verified.push(ctx);
				return double.verify(ctx);
			},
		},
	};
}

/** Boots with the mailing double beside TOTP and alice holding one of its factors, recording `data`. */
async function withMailedFactor(
	options: {
		readonly data?: Record<string, unknown>;
		readonly sender?: RecordingMailSender;
		readonly transactionStore?: MfaTransactionStore;
	} = {},
) {
	const factorStore = createMemoryMfaFactorStore();
	const record = await seedFactor(
		factorStore,
		KIND,
		options.data ?? { addressDigest: recordedDigest(ALICE.email) },
	);
	const { factor, verified } = mailed();
	const sender = options.sender ?? createRecordingMailSender();
	const audit = recordingAuditSink();
	const booted = await boot({
		config: configFor("required"),
		factorStore,
		transactionStore: options.transactionStore ?? createMemoryMfaTransactionStore(),
		auditSink: audit,
		mailSender: sender,
		extraModules: [contributing(factor)],
	});
	return { ...booted, record, audit, sender, verified };
}

const challenge = (agent: Parameters<typeof mfaPost>[0], transaction: string, factorId: string) =>
	mfaPost(agent, "/challenge", { transaction_id: transaction, factor_id: factorId });

describe("a factor's login code", () => {
	it("goes to the login's address when it matches the digest the factor recorded: kept with that address's digest, handed back to the verification, the page answered the masked address and the code's life beside the factor's answer, and the login completes", async () => {
		const { app, record, sender, verified, transactionStore, audit } = await withMailedFactor();
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ sent: true, sent_to: "a***@example.com", expires_in: 600 });
		expect(sender.sent).toEqual([
			{
				purpose: "login_code",
				subject: ALICE.id,
				to: ALICE.email,
				code: expect.any(String),
				expiresAtMs: T0 + 600_000,
			},
		]);
		const kept = await transactionStore.get(transaction);
		expect(kept?.challenge).toMatchObject({ factorId: record.id, kind: KIND });
		expect(kept?.challenge?.state).not.toContain(sender.sent[0]?.code as string);
		expect(audit.of("mfa.challenge.sent")).toHaveLength(1);

		const done = await verify(agent, transaction, record.id, sender.sent[0]?.code);
		expect(done.status).toBe(200);
		expect(verified).toHaveLength(1);
		expect(verified[0]?.addressDigest).toEqual(recordedDigest(ALICE.email));
	});

	it("answers where the code went and how long it lives as the coordinator kept them, whatever the factor's own answer says", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, KIND, {
			addressDigest: recordedDigest(ALICE.email),
		});
		const double = createTestMfaFactor({ kind: KIND, mail: true });
		const claiming: MfaFactor = {
			...double,
			challenge: async (ctx) => {
				const issued = await (double.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
				return { ...issued, response: { sent_to: "elsewhere@example.net", expires_in: 86_400 } };
			},
		};
		const { app } = await boot({
			config: configFor("required"),
			factorStore,
			mailSender: createRecordingMailSender(),
			extraModules: [contributing(claiming)],
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ sent_to: "a***@example.com", expires_in: 600 });
	});

	it.each(["purpose", "code", "expiresAtMs", "addressDigest", "keyId", "digest"])(
		"is answered 503 once, the challenge failed, when reading its mail's %s throws: nothing sent, nothing kept",
		async (field) => {
			const factorStore = createMemoryMfaFactorStore();
			const record = await seedFactor(factorStore, KIND, {
				addressDigest: recordedDigest(ALICE.email),
			});
			const double = createTestMfaFactor({ kind: KIND, mail: true });
			const throwing = (fields: object, key: string) =>
				Object.defineProperty({ ...fields }, key, {
					get: () => {
						throw new Error("the mail cannot be read");
					},
					enumerable: true,
				});
			const unreadable: MfaFactor = {
				...double,
				challenge: async (ctx) => {
					const issued = await (double.challenge as NonNullable<MfaFactor["challenge"]>)(ctx);
					const mail = issued.mail as NonNullable<typeof issued.mail>;
					const digest = mail.addressDigest as NonNullable<typeof mail.addressDigest>;
					return {
						...issued,
						mail:
							field === "keyId" || field === "digest"
								? { ...mail, addressDigest: throwing(digest, field) as never }
								: (throwing(mail, field) as never),
					};
				},
			};
			const sender = createRecordingMailSender();
			const { app, logger, transactionStore } = await boot({
				config: configFor("required"),
				factorStore,
				mailSender: sender,
				extraModules: [contributing(unreadable)],
			});
			const { agent, transaction } = await beginLogin(app);

			const res = await challenge(agent, transaction, record.id);

			expect(res.status, JSON.stringify(res.body)).toBe(503);
			expect(events(logger, "error")).toEqual(["mfa_factor_challenge_unavailable"]);
			expect(sender.sent).toEqual([]);
			expect((await transactionStore.get(transaction))?.version).toBe(0);
		},
	);

	it("answers a mailed enrollment start where the code went and how long it lives as the coordinator kept them, whatever the factor's own answer says", async () => {
		const double = createTestMfaFactor({ kind: KIND, mail: true });
		const claiming: MfaFactor = {
			...double,
			beginEnrollment: async (ctx) => ({
				...(await double.beginEnrollment(ctx)),
				response: { sent_to: "elsewhere@example.net", expires_in: 86_400 },
			}),
		};
		const { app } = await boot({
			config: configFor("required", { enrollment: { requireEmailProof: "never" } }),
			mailSender: createRecordingMailSender(),
			extraModules: [contributing(claiming)],
		});
		const { agent, transaction } = await beginFirstBinding(app);

		const res = await beginEnrollment(agent, transaction, KIND);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ sent_to: "a***@example.com", expires_in: 600 });
	});

	it("is refused when the login's address does not match: 403, mfa.email_address_mismatch recorded with the subject and the kind alone, nothing sent, nothing kept", async () => {
		const { app, record, sender, transactionStore, audit, logger } = await withMailedFactor({
			data: { addressDigest: recordedDigest("old@example.com") },
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "mfa_factor_refused",
			error_description: "This second factor cannot be used: use another",
		});
		expect(sender.sent).toEqual([]);
		expect(await transactionStore.get(transaction)).toMatchObject({
			version: 0,
			challenge: undefined,
		});
		expect(audit.of("mfa.email_address_mismatch")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: KIND, purpose: "login" },
			}),
		]);
		expect(JSON.stringify(audit.events)).not.toContain(ALICE.email);
		expect(audit.of("mfa.challenge.sent")).toEqual([]);
		expect(loggedText(logger)).not.toContain(ALICE.email);
	});

	it("is refused alike when the factor holds no digest it can read, which it mails as null", async () => {
		const { app, record, sender, transactionStore, audit } = await withMailedFactor({ data: {} });
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(403);
		expect(sender.sent).toEqual([]);
		expect((await transactionStore.get(transaction))?.version).toBe(0);
		expect(audit.of("mfa.email_address_mismatch")).toHaveLength(1);
	});

	it("is answered 503 when the digest names a key the ring no longer holds: mfa_factor_unreadable naming it, nothing sent, nothing kept", async () => {
		const { app, record, sender, transactionStore, logger, audit } = await withMailedFactor({
			data: { addressDigest: { ...recordedDigest(ALICE.email), keyId: "k-gone" } },
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_factor_unreadable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "challenge",
			kind: KIND,
			state: "key_unavailable",
			keyId: "k-gone",
		});
		expect(sender.sent).toEqual([]);
		expect((await transactionStore.get(transaction))?.version).toBe(0);
		expect(audit.of("mfa.email_address_mismatch")).toEqual([]);
	});

	it("refused at the sender's limit is answered 429, the pending code cleared, and the transaction kept", async () => {
		const sender = createRecordingMailSender();
		sender.refuseAtLimit();
		const { app, record, transactionStore, audit, logger } = await withMailedFactor({ sender });
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(429);
		expect(res.body).toEqual({
			error: "rate_limited",
			error_description: "Too many codes sent: try again later",
		});
		const kept = await transactionStore.get(transaction);
		expect(kept).not.toBeNull();
		expect(kept?.challenge).toBeUndefined();
		expect(audit.of("mfa.challenge.sent")).toEqual([]);
		expect(
			logger.warn.mock.calls.filter((call) => call[1] === "mfa_mail_refused_at_limit"),
		).toEqual([
			[
				{ route: "challenge", purpose: "login_code", kind: KIND, cleared: true },
				"mfa_mail_refused_at_limit",
			],
		]);
	});

	it("says truthfully whether the pending code was cleared: a clear the store does not write — it answers null, or fails — is logged cleared false, at the limit and at an outage alike", async () => {
		/** A transaction store whose clearing of the challenge answers `clearing`. */
		const clearingWith = (clearing: () => Promise<null>): MfaTransactionStore => {
			const store = createMemoryMfaTransactionStore();
			return {
				...store,
				update: async (id, version, patch) =>
					(patch as { challenge?: unknown }).challenge === null
						? clearing()
						: store.update(id, version, patch),
			};
		};
		const notWritten = async () => null;
		const failing = async (): Promise<null> => {
			throw new Error("transaction store unreachable");
		};
		for (const [clearing, limited] of [
			[notWritten, true],
			[failing, true],
			[notWritten, false],
			[failing, false],
		] as const) {
			const sender = createRecordingMailSender();
			if (limited) sender.refuseAtLimit();
			else sender.failWith(new Error("relay down"));
			const { app, record, logger } = await withMailedFactor({
				sender,
				transactionStore: clearingWith(clearing),
			});
			const { agent, transaction } = await beginLogin(app);

			const res = await challenge(agent, transaction, record.id);

			expect(res.status).toBe(limited ? 429 : 503);
			const line = [...logger.warn.mock.calls, ...logger.error.mock.calls].find(
				(call) => call[1] === "mfa_mail_refused_at_limit" || call[1] === "mfa_mail_unavailable",
			)?.[0];
			expect(line, `${String(limited)} ${clearing.name}`).toMatchObject({ cleared: false });
		}
	});

	it("that the sender cannot send is answered 503 once — mfa_mail_unavailable, carrying neither the code nor the address — the pending code cleared, and the transaction kept", async () => {
		const sender = createRecordingMailSender();
		sender.failWith(new Error("relay unreachable"));
		const { app, record, transactionStore, logger, audit } = await withMailedFactor({ sender });
		const { agent, transaction } = await beginLogin(app);
		const recording = vi.spyOn(sender, "send");

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(503);
		expect(res.body).toEqual({
			error: "temporarily_unavailable",
			error_description: "MFA temporarily unavailable",
		});
		expect(events(logger, "error")).toEqual(["mfa_mail_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({
			route: "challenge",
			purpose: "login_code",
			kind: KIND,
			reason: "outage",
			cleared: true,
		});
		const kept = await transactionStore.get(transaction);
		expect(kept).not.toBeNull();
		expect(kept?.challenge).toBeUndefined();
		const code = (recording.mock.calls[0]?.[0] as { code?: string } | undefined)?.code;
		expect(code).toEqual(expect.any(String));
		if (code === undefined) return;
		expect(loggedText(logger)).not.toContain(code);
		expect(loggedText(logger)).not.toContain(ALICE.email);
		expect(audit.of("mfa.challenge.sent")).toEqual([]);
	});

	it("is answered 503 once, as a mail it cannot send, when no mail sender is wired: nothing kept", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const record = await seedFactor(factorStore, KIND, {
			addressDigest: recordedDigest(ALICE.email),
		});
		const { app, logger, transactionStore } = await boot({
			config: configFor("required"),
			factorStore,
			extraModules: [contributing(mailed().factor)],
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(503);
		expect(events(logger, "error")).toEqual(["mfa_mail_unavailable"]);
		expect(logger.error.mock.calls[0]?.[0]).toMatchObject({ reason: "no_sender" });
		expect((await transactionStore.get(transaction))?.version).toBe(0);
	});

	it("is answered as a spent transaction when the transaction moved on before the code was kept: nothing sent", async () => {
		const store = createMemoryMfaTransactionStore();
		const { app, record, sender } = await withMailedFactor({
			transactionStore: { ...store, update: async () => null },
		});
		const { agent, transaction } = await beginLogin(app);

		const res = await challenge(agent, transaction, record.id);

		expect(res.status).toBe(400);
		expect(res.body.error_description).toBe("Unknown or expired MFA transaction");
		expect(sender.sent).toEqual([]);
	});
});
