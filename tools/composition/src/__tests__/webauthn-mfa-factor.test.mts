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
 * WebAuthn as a second factor through the full set's boot (the template's
 * composition with every package added, `mfa.mode = "required"`, the
 * WebAuthn factor on): a seeded factor asserted by a software passkey after a
 * password login (the MFA ADR's F1, F7, D14, D28). The challenge lists every
 * WebAuthn factor of the subject and is kept on the transaction; a
 * verification takes it, finds the credential by its id, and writes the new
 * sign count by compare-and-set; a lost compare-and-set reads the factor
 * again and checks the assertion again; a counter that did not increase is
 * refused and audited, and only an assertion whose signature verified is
 * judged on its counter; `hwk` or `swk` follows the backup eligibility (BE)
 * registered, and an assertion reporting another is refused.
 */

import type {
	AuditEvent,
	AuditSink,
	MfaFactorData,
	MfaFactorRecord,
	MfaFactorStore,
	MfaTransactionStore,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { createMemoryMfaFactorStore } from "@o3co/auth-provider-core";
import {
	mfaConfigForTests,
	openMfaFactorDataForTests,
	sealMfaFactorDataForTests,
	seedMfaFactor,
	seedTotpFactor,
} from "@o3co/auth-provider-mfa/testing";
import {
	ISSUER,
	ALICE as TEMPLATE_ALICE,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import {
	webauthnMfaFactorConfigForTests,
	webauthnMfaFactorDataForTests,
} from "@o3co/auth-provider-webauthn/testing";
import type { Express } from "express";
import type request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { browser, composeFullSet, type FullSet, MFA_KEY } from "./full-set.fixture.mts";
import { type SoftwarePasskey, softwarePasskey } from "./software-passkey.mts";

// ---------------------------------------------------------------------------
// The composition
// ---------------------------------------------------------------------------

/** The template's user, by the subject her factors are kept under. */
const ALICE = { ...TEMPLATE_ALICE, id: TEMPLATE_ALICE.sub };

/** The MFA section the boot runs on: its key ring seals what is seeded. */
const CONFIG = mfaConfigForTests({ key: MFA_KEY, mode: "required" });

/** An audit sink that keeps what it is handed. */
interface RecordingAuditSink extends AuditSink {
	/** The events of `type`, oldest first. */
	of(type: string): AuditEvent[];
}

function recordingAuditSink(): RecordingAuditSink {
	const events: AuditEvent[] = [];
	return {
		kind: "recording",
		of: (type) => events.filter((event) => event.type === type),
		async record(event) {
			events.push(event);
		},
	};
}

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/**
 * Boots the full set with MFA required and the WebAuthn factor on, over the
 * factor store given (core's memory store by default) and a recording audit
 * sink.
 */
async function boot(stores: { readonly factorStore?: MfaFactorStore } = {}): Promise<{
	readonly app: Express;
	readonly audit: RecordingAuditSink;
	readonly factorStore: MfaFactorStore;
	readonly transactionStore: MfaTransactionStore;
	readonly userSessionStore: UserSessionStore;
}> {
	const factorStore = stores.factorStore ?? createMemoryMfaFactorStore();
	const audit = recordingAuditSink();
	current = await composeFullSet({
		adjust: (config) =>
			({
				...config,
				...CONFIG,
				...webauthnMfaFactorConfigForTests({ enabled: true }),
			}) as typeof config,
		extraOverrides: () => ({ mfaFactorStore: factorStore, auditSink: audit }),
	});
	const { mfaTransactionStore, userSessionStore } = current.handle.components as unknown as {
		readonly mfaTransactionStore: MfaTransactionStore;
		readonly userSessionStore: UserSessionStore;
	};
	return {
		app: current.app,
		audit,
		factorStore,
		transactionStore: mfaTransactionStore,
		userSessionStore,
	};
}

/** A software passkey for the full set's relying party (`auth.test`, the issuer's origin). */
const passkeyFor = (
	options: {
		readonly backupEligible?: boolean;
		readonly backedUp?: boolean;
		readonly counter?: number | "none";
	} = {},
): SoftwarePasskey => softwarePasskey({ rpId: "auth.test", origin: ISSUER, ...options });

/** alice's WebAuthn user handle, which every seeded factor carries. */
const USER_HANDLE = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");

/** What a factor's data is built from beside the passkey: the fields a test sets. */
type DataOptions = Omit<
	Parameters<typeof webauthnMfaFactorDataForTests>[0],
	"credentialId" | "publicKey" | "userHandle"
>;

/**
 * `passkey`'s factor as the WebAuthn package's testing entry builds one: its
 * credential, its count and backup flags as the passkey now has them, alice's
 * user handle, and `options` laid over them.
 */
const factorOf = (passkey: SoftwarePasskey, options: DataOptions = {}) =>
	webauthnMfaFactorDataForTests({
		credentialId: passkey.credentialId,
		publicKey: passkey.publicKey,
		signCount: passkey.counter,
		backupEligible: passkey.backupEligible,
		backedUp: passkey.backedUp,
		userHandle: USER_HANDLE,
		...options,
	});

/** Seeds `passkey` as one of alice's WebAuthn factors, its data sealed under the boot's key ring. */
function seedPasskey(
	factorStore: MfaFactorStore,
	passkey: SoftwarePasskey,
	options: DataOptions = {},
): Promise<MfaFactorRecord> {
	return seedMfaFactor({
		config: CONFIG,
		factorStore,
		subject: ALICE.id,
		...factorOf(passkey, options),
	});
}

/** The record and its opened data, as the factor store now holds them. */
async function storedFactor(
	factorStore: MfaFactorStore,
	record: Pick<MfaFactorRecord, "subject" | "id">,
): Promise<{ readonly record: MfaFactorRecord; readonly data: MfaFactorData }> {
	const stored = (await factorStore.list(record.subject)).find((entry) => entry.id === record.id);
	if (stored === undefined) throw new Error("the factor is gone");
	return { record: stored, data: openMfaFactorDataForTests(CONFIG, stored) };
}

/** A browser on `app`: the full set's cookie jar, a fresh CSRF token on every POST. */
interface Page {
	get(path: string, headers?: Record<string, string>): Promise<request.Response>;
	post(path: string, body: Record<string, unknown>): Promise<request.Response>;
}

/** alice's password login, answered 403 mfa_required: the browser holding the regenerated session, and the transaction. */
async function beginLogin(
	app: Express,
): Promise<{ readonly browser: Page; readonly transaction: string }> {
	const jar = browser();
	const page: Page = {
		get: (path, headers = {}) => jar.get(app, path, headers),
		post: (path, body) => jar.post(app, path, body),
	};
	const res = await page.post("/session/login", {
		username: ALICE.username,
		password: ALICE.password,
	});
	if (res.status !== 403 || res.body.error !== "mfa_required") {
		throw new Error(`the login answered ${res.status} ${JSON.stringify(res.body)}`);
	}
	return { browser: page, transaction: res.body.transaction as string };
}

/** `POST /session/mfa/challenge` for `factorId`: the request options it answers. */
const challenge = (page: Page, transaction: string, factorId: string): Promise<request.Response> =>
	page.post("/session/mfa/challenge", { transaction_id: transaction, factor_id: factorId });

/** `POST /session/mfa/verify` of `proof` for `factorId`. */
const verify = (
	page: Page,
	transaction: string,
	factorId: string,
	proof: unknown,
): Promise<request.Response> =>
	page.post("/session/mfa/verify", { transaction_id: transaction, factor_id: factorId, proof });

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

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
		const create = vi.spyOn(userSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);

		const read = await browser.get("/session/mfa/transaction", { "MFA-Transaction": transaction });
		expect(read.body.factors.map((factor: { kind: string }) => factor.kind)).toEqual([
			"webauthn",
			"webauthn",
		]);
		const options = await challenge(browser, transaction, record.id);
		expect(options.status).toBe(200);
		expect(options.body.rpId).toBe("auth.test");
		expect(options.body.allowCredentials.map((c: { id: string }) => c.id).sort()).toEqual(
			[passkey.credentialId, other.credentialId].sort(),
		);
		const res = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body).toEqual({ message: "Logged in successfully" });
		expect(create).toHaveBeenCalledTimes(1);
		expect(create.mock.calls[0]?.[0]).toMatchObject({
			sub: ALICE.id,
			amr: ["pwd", "hwk", "mfa"],
		});
		const after = await storedFactor(factorStore, record);
		expect(after.data).toEqual(factorOf(passkey, { signCount: 6 }).data);
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

	it.each([
		["backup-eligible and not yet backed up", false],
		["backup-eligible and backed up, a synced one", true],
	])("records swk for a passkey %s: its backup eligibility decides", async (_what, backedUp) => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ backupEligible: true, backedUp, counter: "none" });
		const record = await seedPasskey(factorStore, passkey);
		const { app, userSessionStore } = await boot({ factorStore });
		const create = vi.spyOn(userSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);

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
		expect((await storedFactor(factorStore, answeringRecord)).data).toEqual(
			factorOf(answering, { signCount: 3 }).data,
		);
		expect((await storedFactor(factorStore, namedRecord)).record.version).toBe(0);
	});

	it("accepts an authenticator that keeps no counter, 0 against a stored 0, and keeps it at 0", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: "none" });
		const record = await seedPasskey(factorStore, passkey, { signCount: 0 });
		const { app } = await boot({ factorStore });

		for (let login = 0; login < 2; login++) {
			const { browser, transaction } = await beginLogin(app);
			const options = await challenge(browser, transaction, record.id);
			const res = await verify(
				browser,
				transaction,
				record.id,
				passkey.assert(options.body.challenge),
			);
			expect(res.status, JSON.stringify(res.body)).toBe(200);
		}
		const after = await storedFactor(factorStore, record);
		expect(after.data).toEqual(factorOf(passkey, { signCount: 0 }).data);
		expect(after.record.version).toBe(2);
	});

	it("refuses as invalid an assertion whose backup eligibility is not the one registered, and does not audit it as a clone", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ backupEligible: false, counter: 1 });
		const record = await seedPasskey(factorStore, passkey, { backupEligible: true });
		const { app, audit, userSessionStore } = await boot({ factorStore });
		const create = vi.spyOn(userSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);

		expect(res.status).toBe(401);
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"invalid",
		]);
		expect(create).not.toHaveBeenCalled();
		expect((await storedFactor(factorStore, record)).record.version).toBe(0);
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
		const again = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);
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
 * write lands on the record first — `concurrent`, sealed, relabelled.
 */
function losingFirstUpdate(
	store: MfaFactorStore,
	concurrent: MfaFactorData,
): { readonly store: MfaFactorStore; readonly calls: () => number } {
	let calls = 0;
	return {
		calls: () => calls,
		store: {
			...store,
			update: async (subject, id, expectedVersion, next) => {
				calls++;
				if (calls === 1) {
					const { record } = await storedFactor(store, { subject, id });
					await store.update(subject, id, record.version, {
						data: sealMfaFactorDataForTests(CONFIG, record, concurrent),
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
		const record = await seedPasskey(factorStore, passkey, { signCount: 10 });
		const { app, audit, userSessionStore } = await boot({ factorStore });
		const create = vi.spyOn(userSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);

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
		expect(after.data).toEqual(factorOf(passkey, { signCount: 10 }).data);
		expect(after.record.version).toBe(0);
	});

	it.each([
		["whose signature does not verify", { tampered: true }],
		['whose client data is of type "counter"', { type: "counter" }],
	] as const)(
		"refuses an assertion %s, with a counter below the stored one, as invalid — never audited as sign_count_regression",
		async (_what, forged) => {
			const factorStore = createMemoryMfaFactorStore();
			const passkey = passkeyFor({ counter: 3 });
			const record = await seedPasskey(factorStore, passkey, { signCount: 10 });
			const { app, audit } = await boot({ factorStore });
			const { browser, transaction } = await beginLogin(app);
			const options = await challenge(browser, transaction, record.id);

			const res = await verify(
				browser,
				transaction,
				record.id,
				passkey.assert(options.body.challenge, forged),
			);

			expect(res.status).toBe(401);
			expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
				"invalid",
			]);
			expect((await storedFactor(factorStore, record)).record.version).toBe(0);
		},
	);

	it("reads the factor again after a lost compare-and-set: after a write that left the count, the login completes over that write, keeping what it changed", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: 5 });
		const record = await seedPasskey(factorStore, passkey);
		const losing = losingFirstUpdate(
			factorStore,
			factorOf(passkey, { signCount: 5, transports: ["usb"] }).data,
		);
		const { app } = await boot({ factorStore: losing.store });
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(losing.calls()).toBe(2);
		const after = await storedFactor(factorStore, record);
		expect(after.data).toEqual(factorOf(passkey, { signCount: 6, transports: ["usb"] }).data);
		expect(after.record.label).toBe("renamed");
		expect(after.record.version).toBe(2);
	});

	it("reads the factor again after a lost compare-and-set: after a write that moved the count to the assertion's, the assertion is refused and audited as sign_count_regression", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const passkey = passkeyFor({ counter: 5 });
		const record = await seedPasskey(factorStore, passkey);
		const losing = losingFirstUpdate(factorStore, factorOf(passkey, { signCount: 6 }).data);
		const { app, audit, userSessionStore } = await boot({ factorStore: losing.store });
		const create = vi.spyOn(userSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);

		expect(res.status).toBe(401);
		expect(res.body.error).toBe("mfa_invalid");
		expect(losing.calls()).toBe(1);
		expect(create).not.toHaveBeenCalled();
		expect(audit.of("mfa.verify.failure").map((event) => event.details?.reason)).toEqual([
			"sign_count_regression",
		]);
		expect((await storedFactor(factorStore, record)).data).toEqual(
			factorOf(passkey, { signCount: 6 }).data,
		);
	});
});

describe("beside TOTP", () => {
	it("WebAuthn completes a login for a subject that also holds TOTP, recording hwk and leaving the TOTP factor as it was", async () => {
		const factorStore = createMemoryMfaFactorStore();
		const totp = await seedTotpFactor({ config: CONFIG, factorStore, subject: ALICE.id });
		const passkey = passkeyFor();
		const record = await seedPasskey(factorStore, passkey);
		const { app, userSessionStore } = await boot({ factorStore });
		const create = vi.spyOn(userSessionStore, "create");
		const { browser, transaction } = await beginLogin(app);
		const options = await challenge(browser, transaction, record.id);

		const res = await verify(
			browser,
			transaction,
			record.id,
			passkey.assert(options.body.challenge),
		);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(create.mock.calls[0]?.[0]).toMatchObject({ amr: ["pwd", "hwk", "mfa"] });
		expect((await storedFactor(factorStore, totp.record)).record.version).toBe(0);
	});
});
