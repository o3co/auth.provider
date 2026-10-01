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
 * The MFA enrollment witness across a Store, through the full set's boot (the
 * MFA ADR's D12): the users kept by the test kit's fake Store and read through
 * foundation's `HttpUserRepository`, which writes the witness to the Store's
 * mark endpoint; the factors kept by the same Store or in memory. A first
 * binding marks the witness after the factor is written, a mark that failed
 * is written at the next login, a removal that leaves no record that may
 * count clears it after the removal, and a witness that says the subject enrolled
 * beside no factor stops a password login and every first binding of a
 * federated session — never a binding the lost factors would open.
 */

import type {
	AuditEvent,
	AuditSink,
	MfaFactorStore,
	SupportsMfaEnrollmentWitness,
	UserSessionStore,
} from "@o3co/auth-provider-core";
import { mfaConfigForTests, totpCodeForTests } from "@o3co/auth-provider-mfa/testing";
import { type FakeStore, startFakeStore } from "@o3co/auth-provider-test-kit";
import type { Express } from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	browser,
	composeFullSet,
	type FullSet,
	type FullSetOptions,
	GITHUB_HANDLE,
	GITHUB_LANDING,
	MFA_KEY,
} from "./full-set.fixture.mts";

/** A user the Store holds and logs in with a password. */
const ALICE = { id: "u-store-alice", username: "store-alice", password: "store-alice-password" };
/** A user the Store holds and the GitHub federation signs in, with no address. */
const DAVE = { id: "u-store-dave", username: "store-dave", password: "store-dave-password" };

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

/** RFC 4648 §6 base32, as a TOTP enrollment hands its secret over. */
function fromBase32(text: string): Buffer {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	const bytes: number[] = [];
	let value = 0;
	let bits = 0;
	for (const character of text.replace(/=+$/, "")) {
		const index = alphabet.indexOf(character);
		if (index === -1) throw new Error("the enrollment answered a secret that is not base32");
		value = (value << 5) | index;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			bytes.push((value >>> bits) & 0xff);
		}
	}
	return Buffer.from(bytes);
}

let current: FullSet | undefined;
let store: FakeStore;

beforeEach(async () => {
	store = await startFakeStore({
		users: [
			{ id: ALICE.id, username: ALICE.username, password: ALICE.password },
			{
				id: DAVE.id,
				username: DAVE.username,
				password: DAVE.password,
				tokens: [GITHUB_HANDLE],
			},
		],
	});
});

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
	await store.close();
});

/** Where the MFA factors are kept beside the Store's users. */
type Factors = "store" | "memory";

/**
 * Boots the full set with its users in the fake Store, the witness written
 * there, the factors where `factors` says, and a recording audit sink; MFA
 * required unless `options.adjust` says otherwise.
 */
async function boot(
	factors: Factors,
	options: FullSetOptions = {},
): Promise<FullSet & { readonly audit: RecordingAuditSink }> {
	const audit = recordingAuditSink();
	current = await composeFullSet({
		userRepositoryAt: store.urls,
		...(factors === "store" ? { mfaFactorStoreAt: store.urls } : {}),
		adjust: (config) => ({ ...config, ...mfaConfigForTests({ key: MFA_KEY, mode: "required" }) }),
		extraOverrides: () => ({ auditSink: audit }),
		...options,
	});
	return { ...current, audit };
}

/** The components the scenarios read, as the full set wires them. */
const storesOf = ({ handle }: FullSet) =>
	handle.components as unknown as {
		readonly mfaFactorStore: MfaFactorStore;
		readonly userSessionStore: UserSessionStore;
		readonly userRepository: SupportsMfaEnrollmentWitness;
	};

/** What the MFA module logged at warn under `event`. */
const warned = ({ logger }: FullSet, event: string) =>
	logger.lines.filter((line) => line.level === "warn" && line.args[1] === event);

/** The Store's request log from `from` on, by endpoint. */
const endpointsSince = (from: number) => store.requests.slice(from).map(({ endpoint }) => endpoint);

/**
 * Alice's first login under `mfa.mode = "required"`: the password, `403
 * mfa_enrollment_required`, a TOTP enrollment and its completion. Answers the
 * completion, the factor's secret and the browser.
 */
async function firstBinding(app: Express) {
	const page = browser();
	const login = await page.post(
		app,
		"/session/login",
		{ username: ALICE.username, password: ALICE.password },
		{ form: true },
	);
	expect(login.status, JSON.stringify(login.body)).toBe(403);
	expect(login.body.error).toBe("mfa_enrollment_required");
	const transaction = login.body.transaction as string;
	const begun = await page.post(app, "/session/mfa/enrollment", {
		transaction_id: transaction,
		kind: "totp",
	});
	expect(begun.status, JSON.stringify(begun.body)).toBe(200);
	const secret = fromBase32(begun.body.secret as string);
	const done = await page.post(app, "/session/mfa/enrollment/complete", {
		transaction_id: transaction,
		proof: totpCodeForTests(secret),
	});
	return { done, secret, page };
}

describe.each(["store", "memory"] as const)(
	"the witness at a first binding, the factors kept in %s",
	(factors) => {
		it("marks the subject enrolled in the Store once its first factor is written, and the login completes", async () => {
			const set = await boot(factors);
			const create = vi.spyOn(storesOf(set).mfaFactorStore, "create");
			const mark = vi.spyOn(storesOf(set).userRepository, "markMfaEnrolled");
			const { done } = await firstBinding(set.app);
			expect(done.status, JSON.stringify(done.body)).toBe(200);
			expect(done.body.factor).toMatchObject({ kind: "totp" });

			expect(mark.mock.calls).toEqual([[ALICE.id, true]]);
			const created = create.mock.invocationCallOrder;
			expect(created.length).toBeGreaterThan(0);
			expect(Math.max(...created)).toBeLessThan(mark.mock.invocationCallOrder[0] as number);
			expect(store.enrolled(ALICE.id)).toBe(true);
			const marks = store.requests.filter(({ endpoint }) => endpoint === "markMfaEnrolled");
			expect(marks.map(({ body }) => body)).toEqual([{ subject: ALICE.id, enrolled: true }]);
			const kept = await storesOf(set).mfaFactorStore.list(ALICE.id);
			expect(kept.map(({ kind }) => kind)).toContain("totp");
			if (factors === "store") {
				const endpoints = endpointsSince(0);
				expect(endpoints.lastIndexOf("create")).toBeLessThan(endpoints.indexOf("markMfaEnrolled"));
			}
			expect(warned(set, "mfa_enrollment_witness_unwritten")).toEqual([]);
		});

		it("completes the login when the Store answers the mark 503, with one warning, and writes the mark at the next TOTP login", async () => {
			const set = await boot(factors);
			store.answer("markMfaEnrolled", () => ({ status: 503 }));
			const { done, secret } = await firstBinding(set.app);
			expect(done.status, JSON.stringify(done.body)).toBe(200);
			expect(store.enrolled(ALICE.id)).toBeUndefined();
			expect(warned(set, "mfa_enrollment_witness_unwritten")).toHaveLength(1);

			store.answer("markMfaEnrolled", undefined);
			const page = browser();
			const login = await page.post(
				set.app,
				"/session/login",
				{ username: ALICE.username, password: ALICE.password },
				{ form: true },
			);
			expect(login.status, JSON.stringify(login.body)).toBe(403);
			expect(login.body.error).toBe("mfa_required");
			const transaction = login.body.transaction as string;
			const factorId = done.body.factor.id as string;
			const challenge = await page.post(set.app, "/session/mfa/challenge", {
				transaction_id: transaction,
				factor_id: factorId,
			});
			expect(challenge.status, JSON.stringify(challenge.body)).toBe(200);
			// One step on from the code the enrollment spent, which a replay check refuses.
			const verified = await page.post(set.app, "/session/mfa/verify", {
				transaction_id: transaction,
				factor_id: factorId,
				proof: totpCodeForTests(secret, { offset: 1 }),
			});
			expect(verified.status, JSON.stringify(verified.body)).toBe(200);
			expect(store.enrolled(ALICE.id)).toBe(true);
			expect(warned(set, "mfa_enrollment_witness_unwritten")).toHaveLength(1);
		});

		it("answers a password login 503 once the factors are lost while the Store says the subject enrolled, and writes nothing", async () => {
			const set = await boot(factors);
			const { done } = await firstBinding(set.app);
			expect(done.status, JSON.stringify(done.body)).toBe(200);
			expect(store.enrolled(ALICE.id)).toBe(true);
			await storesOf(set).mfaFactorStore.removeAllForSubject(ALICE.id);
			const create = vi.spyOn(storesOf(set).userSessionStore, "create");
			const from = store.requests.length;

			const csrf = await request(set.app).get("/session/csrf");
			const login = await request(set.app)
				.post("/session/login")
				.set("Cookie", ([] as string[]).concat(csrf.headers["set-cookie"] ?? []))
				.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
				.type("form")
				.send({ username: ALICE.username, password: ALICE.password });

			expect(login.status, JSON.stringify(login.body)).toBe(503);
			expect(login.body.error).toBe("temporarily_unavailable");
			expect(set.audit.of("mfa.enrollment_state_inconsistent")).toEqual([
				expect.objectContaining({
					subject: ALICE.id,
					details: expect.objectContaining({ purpose: "login", witness: "enrolled" }),
				}),
			]);
			expect(endpointsSince(from)).not.toContain("create");
			expect(endpointsSince(from)).not.toContain("markMfaEnrolled");
			expect(create).not.toHaveBeenCalled();
			expect(await storesOf(set).mfaFactorStore.list(ALICE.id)).toEqual([]);
		});
	},
);

describe.each(["store", "memory"] as const)(
	"the witness at a removal, the factors kept in %s",
	(factors) => {
		it("sends {enrolled: false} to the Store once the last record that may count is removed, after the removal", async () => {
			const set = await boot(factors, {
				adjust: (config) => ({
					...config,
					...mfaConfigForTests({ key: MFA_KEY, mode: "optional" }),
				}),
			});
			const page = browser();
			const login = await page.post(
				set.app,
				"/session/login",
				{ username: ALICE.username, password: ALICE.password },
				{ form: true },
			);
			expect(login.status, JSON.stringify(login.body)).toBe(200);
			const begun = await page.post(set.app, "/session/mfa/enrollment", { kind: "totp" });
			expect(begun.status, JSON.stringify(begun.body)).toBe(200);
			const done = await page.post(set.app, "/session/mfa/enrollment/complete", {
				transaction_id: begun.body.transaction,
				proof: totpCodeForTests(fromBase32(begun.body.secret as string)),
			});
			expect(done.status, JSON.stringify(done.body)).toBe(200);
			expect(store.enrolled(ALICE.id)).toBe(true);
			const from = store.requests.length;

			const removed = await page.post(set.app, "/session/mfa/factors/remove", {
				factor_id: done.body.factor.id,
			});

			expect(removed.status, JSON.stringify(removed.body)).toBe(200);
			const marks = store.requests
				.slice(from)
				.filter(({ endpoint }) => endpoint === "markMfaEnrolled");
			expect(marks.map(({ body }) => body)).toEqual([{ subject: ALICE.id, enrolled: false }]);
			expect(store.enrolled(ALICE.id)).toBe(false);
			if (factors === "store") {
				const endpoints = endpointsSince(from);
				expect(endpoints.indexOf("delete")).toBeLessThan(endpoints.indexOf("markMfaEnrolled"));
			}
		});

		it("sends nothing to the Store's mark endpoint when a record is removed beside a counting factor", async () => {
			const set = await boot(factors);
			const { done, page } = await firstBinding(set.app);
			expect(done.status, JSON.stringify(done.body)).toBe(200);
			const listed = await page.get(set.app, "/session/mfa/factors");
			expect(listed.status, JSON.stringify(listed.body)).toBe(200);
			const codes = (listed.body.factors as { id: string; kind: string }[]).find(
				({ kind }) => kind === "recovery_code",
			);
			if (codes === undefined) throw new Error("the first binding issued no recovery codes");
			const from = store.requests.length;

			const removed = await page.post(set.app, "/session/mfa/factors/remove", {
				factor_id: codes.id,
			});

			expect(removed.status, JSON.stringify(removed.body)).toBe(200);
			expect(endpointsSince(from)).not.toContain("markMfaEnrolled");
			expect(store.enrolled(ALICE.id)).toBe(true);
		});
	},
);

describe.each(["store", "memory"] as const)(
	"the witness a federated login reads through authenticateByToken, the factors kept in %s",
	(factors) => {
		/** A link endpoint the start only checks is configured: no link completes here. */
		const linkFederatedIdentityUrl = () => new URL("/link", store.urls.authenticateUrl).href;

		/** Dave signed in through the GitHub federation on one cookie jar, and a CSRF pair; MFA optional. */
		async function federatedDave(witness: unknown) {
			if (witness !== undefined) {
				await store.close();
				store = await startFakeStore({
					users: [
						{
							id: DAVE.id,
							username: DAVE.username,
							password: DAVE.password,
							tokens: [GITHUB_HANDLE],
							claims: { mfaEnrolled: witness },
						},
					],
				});
			}
			const set = await boot(factors, {
				userRepositoryAt: { ...store.urls, linkFederatedIdentityUrl: linkFederatedIdentityUrl() },
				...(factors === "store" ? { mfaFactorStoreAt: store.urls } : {}),
				adjust: (config) => ({
					...config,
					...mfaConfigForTests({ key: MFA_KEY, mode: "optional" }),
				}),
			});
			const agent = request.agent(set.app);
			const start = await agent.get("/session/oauth/federation/github");
			expect(start.status).toBe(302);
			const state = new URL(start.headers.location as string).searchParams.get("state") ?? "";
			const callback = await agent
				.get("/session/oauth/federation/github/callback")
				.query({ code: "github-code", state });
			expect(callback.status, JSON.stringify(callback.body)).toBe(302);
			expect(callback.headers.location).toBe(GITHUB_LANDING);
			const csrf = await agent.get("/session/csrf");
			return {
				set,
				agent,
				header: csrf.body.header_name as string,
				token: csrf.body.csrf_token as string,
			};
		}

		/** The three first bindings a signed-in session can start: a factor, a passkey and a link. */
		async function firstBindings(signedIn: Awaited<ReturnType<typeof federatedDave>>) {
			const { agent, header, token } = signedIn;
			const enrollment = await agent
				.post("/session/mfa/enrollment")
				.set(header, token)
				.send({ kind: "totp" });
			const registration = await agent
				.post("/oauth/webauthn/registration/options")
				.set(header, token)
				.send({});
			const link = await agent
				.get("/session/oauth/federation/google?link=1")
				.set("Sec-Fetch-Site", "same-origin");
			return { enrollment, registration, link };
		}

		it.each([
			["true", true, "enrolled"],
			['"true", which is not a boolean', "true", "malformed"],
		] as const)(
			"refuses every first binding 503 when it answers mfaEnrolled %s beside no factor, recording the inconsistency",
			async (_what, witness, read) => {
				const signedIn = await federatedDave(witness);
				const answers = await firstBindings(signedIn);
				for (const [binding, answer] of Object.entries(answers)) {
					expect(answer.status, `${binding}: ${JSON.stringify(answer.body)}`).toBe(503);
				}
				const recorded = signedIn.set.audit.of("mfa.enrollment_state_inconsistent");
				expect(recorded).toHaveLength(3);
				for (const event of recorded) {
					expect(event).toMatchObject({
						subject: DAVE.id,
						details: expect.objectContaining({ purpose: "session", witness: read }),
					});
				}
				expect(await storesOf(signedIn.set).mfaFactorStore.list(DAVE.id)).toEqual([]);
			},
		);

		it("admits every first binding when it answers no witness, as a subject that never enrolled", async () => {
			const signedIn = await federatedDave(undefined);
			const { enrollment, registration, link } = await firstBindings(signedIn);
			expect(enrollment.status, JSON.stringify(enrollment.body)).toBe(200);
			expect(registration.status, JSON.stringify(registration.body)).toBe(200);
			expect(link.status, JSON.stringify(link.body)).toBe(302);
			expect(signedIn.set.audit.of("mfa.enrollment_state_inconsistent")).toEqual([]);
		});
	},
);

describe("the boot warning for a user repository that cannot write the witness", () => {
	it("is said once when the Store's user repository has no witness URL, and not at all when it has one", async () => {
		const without = await boot("memory", {
			userRepositoryAt: {
				authenticateUrl: store.urls.authenticateUrl,
				authenticateByTokenUrl: store.urls.authenticateByTokenUrl,
			},
		});
		expect(warned(without, "mfa_enrollment_witness_unwritable")).toHaveLength(1);
		await without.handle.dispose();
		current = undefined;

		const withUrl = await boot("memory");
		expect(warned(withUrl, "mfa_enrollment_witness_unwritable")).toEqual([]);
	});
});
