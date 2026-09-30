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
 * WebAuthn as a second factor through `createApp`, a seeded factor asserted
 * by a software passkey after a password login (the MFA ADR's F1, F7, D14,
 * D21, D28): the challenge lists every WebAuthn factor of the subject and is
 * kept on the transaction; a verification takes it, finds the credential by
 * its id, and writes the new sign count by compare-and-set; a lost
 * compare-and-set reads the factor again and checks the assertion again; a
 * counter that did not increase is refused and audited; and the factor
 * completes a login while the subject's guessable proofs are held.
 */

import {
	createMemoryMfaFactorStore,
	createMemoryMfaTransactionStore,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { sealMfaFactorDataForTests, seedTotpFactor } from "@o3co/auth-provider-mfa/testing";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	ALICE,
	beginLogin,
	boot,
	CONFIG,
	challenge,
	disposeAll,
	LOCKOUT,
	passkeyFor,
	seedPasskey,
	storedFactor,
	USER_HANDLE,
	verify,
} from "./mfaComposition.mjs";

afterEach(disposeAll);

const NOT_ACCEPTED = {
	error: "mfa_invalid",
	error_description: "Second factor not accepted",
};

describe("a WebAuthn login", () => {
	it("goes password, 403 mfa_required, a challenge listing every WebAuthn factor of alice, the assertion — and establishes the session with hwk and mfa, the factor's count written", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: 5 });
		const other = passkeyFor();
		const record = await seedPasskey(factorStore, passkey);
		const second = await seedPasskey(factorStore, other);
		const { app, audit, transactionStore, userSessionStore } = await boot({ factorStore });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);

		const read = await browser.get("/session/mfa/transaction", { "MFA-Transaction": transaction });
		expect(read.body.factors.map((factor: { kind: string }) => factor.kind)).toEqual([
			"webauthn",
			"webauthn",
		]);
		const options = await challenge(browser, transaction, record.id);
		expect(options.status).toBe(200);
		expect(options.body.rpId).toBe("test.example");
		expect(options.body.allowCredentials.map((c: { id: string }) => c.id).sort()).toEqual(
			[passkey.credentialId, other.credentialId].sort(),
		);
		const res = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully" });
		expect(create).toHaveBeenCalledTimes(1);
		expect(create.mock.calls[0]?.[0]).toMatchObject({
			sub: ALICE.id,
			amr: ["pwd", "hwk", "mfa"],
		});
		const after = await storedFactor(factorStore, record);
		expect(after.data).toMatchObject({ signCount: 6, backedUp: false, userHandle: USER_HANDLE });
		expect(after.record.version).toBe(1);
		expect((await storedFactor(factorStore, second)).record.version).toBe(0);
		expect(await transactionStore.get(transaction)).toBeNull();
		expect(audit.of("mfa.verified")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "webauthn", purpose: "login" },
			}),
		]);
		expect(audit.of("mfa.verify.failure")).toEqual([]);
	});

	it("records swk for a passkey whose backup state is set: a synced one", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ backedUp: true, counter: "none" });
		const record = await seedPasskey(factorStore, passkey);
		const { app, userSessionStore } = await boot({ factorStore });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(create.mock.calls[0]?.[0]).toMatchObject({ amr: ["pwd", "swk", "mfa"] });
	});

	it("verifies the factor whose credential answered, whichever of alice's WebAuthn factors the request names", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const named = passkeyFor();
		const answering = passkeyFor({ counter: 2 });
		const namedRecord = await seedPasskey(factorStore, named);
		const answeringRecord = await seedPasskey(factorStore, answering);
		const { app } = await boot({ factorStore });
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, namedRecord.id);

		const res = await verify(
			browser,
			transaction,
			namedRecord.id,
			answering.assert(options.body.challenge, { userHandle: USER_HANDLE }),
		);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect((await storedFactor(factorStore, answeringRecord)).data.signCount).toBe(3);
		expect((await storedFactor(factorStore, namedRecord)).record.version).toBe(0);
	});

	it("accepts an authenticator that keeps no counter, 0 against a stored 0, and keeps it at 0", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: "none" });
		const record = await seedPasskey(factorStore, passkey, 0);
		const { app } = await boot({ factorStore });

		for (let login = 0; login < 2; login++) {
			const { browser, transaction } = await beginLogin(app);
			const options = await challenge(browser, transaction, record.id);
			const res = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));
			expect(res.status, JSON.stringify(res.body)).toBe(200);
		}
		const after = await storedFactor(factorStore, record);
		expect(after.data.signCount).toBe(0);
		expect(after.record.version).toBe(2);
	});
});

describe("the challenge, kept on the transaction", () => {
	it("is kept sealed on the transaction, and taken by a verification: answered a second time, it is refused, and a new one is asked for", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: 1 });
		const record = await seedPasskey(factorStore, passkey);
		const { app, audit, transactionStore } = await boot({ factorStore });
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);
		const kept = (await transactionStore.get(transaction))?.challenge;
		expect(kept).toMatchObject({ factorId: record.id, kind: "webauthn" });
		expect(kept?.state).not.toContain(options.body.challenge);

		// The first answer is refused: its signature is not over what it sends.
		const tampered = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge, { tampered: true }),
		);
		expect(tampered.status).toBe(401);
		expect((await transactionStore.get(transaction))?.challenge).toBeUndefined();
		// A right answer to the same challenge now has no challenge to answer.
		const again = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));
		expect(again.status).toBe(401);
		expect(again.body).toEqual({ ...NOT_ACCEPTED, attempts_remaining: 3 });
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"invalid",
			"expired",
		]);
		// A new challenge is answered.
		const fresh = await challenge(browser, transaction, record.id);
		const res = await verify(browser, transaction, record.id, passkey.assert(fresh.body.challenge));
		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});
});

/**
 * A factor store whose first `update` loses its compare-and-set: another
 * write lands on the record first — `concurrent`'s data, sealed, or the data
 * as it is, relabelled.
 */
function losingFirstUpdate(
	store: MfaFactorStore,
	concurrent?: (data: Record<string, unknown>) => Record<string, unknown>,
): { readonly store: MfaFactorStore; readonly calls: () => number } {
	let calls = 0;
	return {
		calls: () => calls,
		store: {
			...store,
			update: async (subject, id, expectedVersion, next) => {
				calls++;
				if (calls === 1) {
					const { record, data } = await storedFactor(store, { subject, id });
					await store.update(subject, id, record.version, {
						data:
							concurrent === undefined
								? record.data
								: sealMfaFactorDataForTests(CONFIG, record, concurrent(data)),
						label: "renamed",
						lastUsedAt: record.lastUsedAt,
					});
				}
				return store.update(subject, id, expectedVersion, next);
			},
		},
	};
}

describe("the sign count", () => {
	it("refuses a counter that did not increase over the stored one: 401, audited as sign_count_regression, no session, the factor left as it was", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: 3 });
		const record = await seedPasskey(factorStore, passkey, 10);
		const { app, audit, userSessionStore } = await boot({ factorStore });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));

		expect(res.status).toBe(401);
		expect(res.body).toEqual({ ...NOT_ACCEPTED, attempts_remaining: 4 });
		expect(audit.of("mfa.verify.failure")).toEqual([
			expect.objectContaining({
				subject: ALICE.id,
				details: { kind: "webauthn", purpose: "login", reason: "sign_count_regression" },
			}),
		]);
		expect(audit.of("mfa.verified")).toEqual([]);
		expect(create).not.toHaveBeenCalled();
		const after = await storedFactor(factorStore, record);
		expect(after.data.signCount).toBe(10);
		expect(after.record.version).toBe(0);
	});

	it("reads the factor again after a lost compare-and-set and checks the assertion again: after a write that left the count, the login completes", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: 5 });
		const record = await seedPasskey(factorStore, passkey);
		const losing = losingFirstUpdate(factorStore);
		const { app } = await boot({ factorStore: losing.store });
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(losing.calls()).toBe(2);
		const after = await storedFactor(factorStore, record);
		expect(after.data.signCount).toBe(6);
		expect(after.record.label).toBe("renamed");
		expect(after.record.version).toBe(2);
	});

	it("reads the factor again after a lost compare-and-set: after a write that moved the count to the assertion's, the assertion is refused and audited as sign_count_regression", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: 5 });
		const record = await seedPasskey(factorStore, passkey);
		const losing = losingFirstUpdate(factorStore, (data) => ({ ...data, signCount: 6 }));
		const { app, audit, userSessionStore } = await boot({ factorStore: losing.store });
		const create = vi.spyOn(userSessionStore as UserSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("mfa_invalid");
		expect(losing.calls()).toBe(1);
		expect(create).not.toHaveBeenCalled();
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"sign_count_regression",
		]);
		expect((await storedFactor(factorStore, record)).data.signCount).toBe(6);
	});
});

describe("beside TOTP", () => {
	it("completes a login while alice's guessable proofs are held", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const transactionStore = createMemoryMfaTransactionStore();
		await seedTotpFactor({ config: CONFIG, factorStore, subject: ALICE.id });
		const passkey = passkeyFor();
		const record = await seedPasskey(factorStore, passkey);
		// Failures until the subject lock holds guessable proofs.
		for (;;) {
			const reserved = await transactionStore.reserveSubjectAttempt(
				ALICE.id,
				Date.now(),
				LOCKOUT,
				undefined,
			);
			if (!reserved.ok) break;
			await transactionStore.settleSubjectAttempt(ALICE.id, reserved.reservation, "failure");
		}
		expect(
			await transactionStore.reserveSubjectAttempt(ALICE.id, Date.now(), LOCKOUT, undefined),
		).toMatchObject({ ok: false, hold: "backoff" });
		const { app } = await boot({ factorStore, transactionStore });
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(browser, transaction, record.id, passkey.assert(options.body.challenge));

		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});
});
