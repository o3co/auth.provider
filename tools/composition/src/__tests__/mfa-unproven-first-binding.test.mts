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
 * A first factor bound from the account page without the account-email
 * proof, through the full set's boot (`mfa.mode = "optional"`, every store in
 * memory): the binding is recorded by the sign-in alone and adds nothing to
 * the session it is made in (the MFA ADR's D24). For each way such a binding
 * is made — in a session signed in through a federation, a WebAuthn factor,
 * an email factor under `requireEmailProof = "never"`, and a binding whose
 * session proof stood at its admission and no longer does at its completion
 * — the session's record is left as it was, its express id is not renewed,
 * a code minted after the binding carries the claims one minted before it
 * did, and the session then steps up with the factor it bound.
 */

import { randomBytes } from "node:crypto";
import {
	type AppConfig,
	createMemoryMfaTransactionStore,
	type MfaFactorStore,
	type MfaTransactionStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	mfaConfigForTests,
	mfaEmailFactorConfigForTests,
	totpCodeForTests,
} from "@o3co/auth-provider-mfa/testing";
import {
	ALICE,
	basic,
	ISSUER,
	PKCE,
	WEB,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { webauthnMfaFactorConfigForTests } from "@o3co/auth-provider-webauthn/testing";
import type { Express } from "express";
import request from "supertest";
import { afterEach, expect, it, vi } from "vitest";
import {
	browser,
	composeFullSet,
	type FullSet,
	type FullSetOptions,
	fromBase32,
	MFA_KEY,
} from "./full-set.fixture.mts";
import { softwarePasskey } from "./software-passkey.mts";

type Page = ReturnType<typeof browser>;

const booted: FullSet[] = [];

afterEach(async () => {
	await Promise.all(booted.splice(0).map((set) => set.handle.dispose()));
	vi.restoreAllMocks();
});

/** Boots the full set with MFA optional, `requireEmailProof` as given, and `extra` laid over the configuration. */
async function boot(
	requireEmailProof: "when-mail" | "never",
	extra: Record<string, unknown> = {},
	options: FullSetOptions = {},
): Promise<FullSet> {
	const set = await composeFullSet({
		adjust: (config: AppConfig): AppConfig => {
			const core = (config as { core?: { federations?: Record<string, object> } }).core;
			return {
				...config,
				...mfaConfigForTests({ key: MFA_KEY, mode: "optional", enrollment: { requireEmailProof } }),
				// The fake upstream reports no auth_time: the callback stands for the
				// recent primary a first binding in a federated session needs.
				core: {
					...core,
					federations: {
						...core?.federations,
						oidc: { ...core?.federations?.oidc, callbackMeetsFreshness: true },
					},
				},
				...extra,
			} as unknown as AppConfig;
		},
		...options,
	});
	booted.push(set);
	return set;
}

/** The stores the tests read, as the full set wires them. */
const storesOf = (set: FullSet) =>
	set.handle.components as unknown as {
		readonly mfaFactorStore: MfaFactorStore;
		readonly userSessionStore: UserSessionStore;
	};

/** Runs `signIn` with the session store's `create` watched: the sid of the session it wrote. */
async function watchingCreate(set: FullSet, signIn: () => Promise<void>): Promise<string> {
	const create = vi.spyOn(storesOf(set).userSessionStore, "create");
	await signIn();
	const sid = (create.mock.calls.at(-1)?.[0] as { sid?: unknown } | undefined)?.sid;
	create.mockRestore();
	if (typeof sid !== "string") throw new Error("the sign-in wrote no session");
	return sid;
}

/** Alice's password login on `page`: the sid of her session. */
const passwordSignIn = (set: FullSet, page: Page): Promise<string> =>
	watchingCreate(set, async () => {
		const res = await page.post(
			set.app,
			"/session/login",
			{ username: ALICE.username, password: ALICE.password },
			{ form: true },
		);
		expect(res.status, JSON.stringify(res.body)).toBe(200);
	});

/** Alice signed in through the `oidc` federation on `page`, its callback run: the sid of her session. */
const federatedSignIn = (set: FullSet, page: Page): Promise<string> =>
	watchingCreate(set, async () => {
		const start = await page.get(set.app, "/session/oauth/federation/oidc");
		expect(start.status).toBe(302);
		const answer = set.upstreams.oidc.authorize(start.headers.location as string);
		const callback = await page.get(
			set.app,
			`/session/oauth/federation/oidc/callback?${new URLSearchParams({
				code: answer.code,
				state: answer.state ?? "",
				...(answer.iss === undefined ? {} : { iss: answer.iss }),
			})}`,
		);
		expect(callback.status, JSON.stringify(callback.body)).toBe(302);
	});

/** The express session cookie the browser holds. */
const sessionCookieOf = (page: Page): string | undefined =>
	page.cookies().find((cookie) => cookie.startsWith("auth.session="));

/** Whether `res` set the express session cookie. */
const setsSessionCookie = (res: request.Response): boolean =>
	([] as string[])
		.concat(res.headers["set-cookie"] ?? [])
		.some((line) => line.startsWith("auth.session="));

/** A JWT's claims, unverified: the issuing replica signed it a line earlier. */
const claimsOf = (jwt: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString("utf8"));

/** A code for the web client minted from the browser's session, redeemed: its tokens' amr, acr and auth_time. */
async function tokenClaims(app: Express, page: Page) {
	const authorized = await page.get(
		app,
		`/oauth/authorize?${new URLSearchParams({
			response_type: "code",
			client_id: WEB.id,
			redirect_uri: WEB.redirectUri,
			scope: "openid profile offline_access",
			state: "binding-state",
			nonce: `binding-${randomBytes(4).toString("hex")}`,
			code_challenge: PKCE.challenge,
			code_challenge_method: "S256",
		})}`,
	);
	expect(authorized.status, JSON.stringify(authorized.body)).toBe(302);
	const back = new URL(authorized.headers.location as string, ISSUER);
	expect(back.origin + back.pathname).toBe(WEB.redirectUri);
	const code = back.searchParams.get("code");
	if (code === null) throw new Error(`no code: ${back.toString()}`);
	const tokens = await request(app)
		.post("/oauth/token")
		.set("Authorization", basic(WEB))
		.type("form")
		.send({
			grant_type: "authorization_code",
			code,
			redirect_uri: WEB.redirectUri,
			code_verifier: PKCE.verifier,
		});
	expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
	return [tokens.body.id_token, tokens.body.access_token].map((token: string) => {
		const { amr, acr, auth_time } = claimsOf(token);
		return { amr, acr, auth_time };
	});
}

/** What the session and the browser held before the binding. */
interface Before {
	readonly sid: string;
	readonly record: unknown;
	readonly cookie: string | undefined;
	readonly claims: Awaited<ReturnType<typeof tokenClaims>>;
}

async function before(set: FullSet, page: Page, sid: string): Promise<Before> {
	const record = await storesOf(set).userSessionStore.get(sid);
	expect(record?.authentication?.mfaAt).toBeUndefined();
	return { sid, record, cookie: sessionCookieOf(page), claims: await tokenClaims(set.app, page) };
}

/**
 * The four things a binding that adds nothing leaves as they were: the
 * session's record, its express id (no cookie set, the browser's unchanged),
 * and the claims of a code minted after it; and the binding recorded by the
 * sign-in alone.
 */
async function leftAsItWas(
	set: FullSet,
	page: Page,
	was: Before,
	bound: request.Response,
	binding: "password" | "federated",
): Promise<string> {
	expect(bound.status, JSON.stringify(bound.body)).toBe(200);
	expect(bound.body.message).toBeUndefined();
	const factorId = bound.body.factor.id as string;
	const records = await storesOf(set).mfaFactorStore.list(ALICE.sub);
	expect(records.find((record) => record.id === factorId)?.binding).toBe(binding);
	expect(await storesOf(set).userSessionStore.get(was.sid)).toEqual(was.record);
	expect(setsSessionCookie(bound)).toBe(false);
	expect(sessionCookieOf(page)).toBe(was.cookie);
	expect(await tokenClaims(set.app, page)).toEqual(was.claims);
	return factorId;
}

/** `POST /session/mfa/step-up`: the step-up transaction opened for alice's counting factor. */
async function openStepUp(set: FullSet, page: Page): Promise<string> {
	const opened = await page.post(set.app, "/session/mfa/step-up", {});
	expect(opened.status, JSON.stringify(opened.body)).toBe(200);
	return opened.body.transaction as string;
}

/** A step-up's verification of `proof` for `factorId`, answered verified; the session's record after it. */
async function steppedUp(
	set: FullSet,
	page: Page,
	sid: string,
	transaction: string,
	factorId: string,
	proof: unknown,
) {
	const verified = await page.post(set.app, "/session/mfa/verify", {
		transaction_id: transaction,
		factor_id: factorId,
		proof,
	});
	expect(verified.status, JSON.stringify(verified.body)).toBe(200);
	expect(verified.body).toEqual({ step_up: "verified" });
	const record = await storesOf(set).userSessionStore.get(sid);
	expect(record?.authentication?.mfaAt).toBeInstanceOf(Date);
	return record;
}

/** A TOTP factor bound from the account page: the completion, and the secret. */
async function bindTotp(set: FullSet, page: Page) {
	const begun = await page.post(set.app, "/session/mfa/enrollment", { kind: "totp" });
	expect(begun.status, JSON.stringify(begun.body)).toBe(200);
	const secret = fromBase32(begun.body.secret as string);
	const bound = await page.post(set.app, "/session/mfa/enrollment/complete", {
		transaction_id: begun.body.transaction,
		proof: totpCodeForTests(secret),
	});
	return { bound, secret };
}

it("a first TOTP factor bound in a session signed in through a federation is recorded federated and leaves the session as it was; the session then steps up with it", async () => {
	const set = await boot("never");
	const page = browser();
	const sid = await federatedSignIn(set, page);
	const was = await before(set, page, sid);
	expect(was.claims[0]?.amr).not.toContain("otp");

	const { bound, secret } = await bindTotp(set, page);

	const factorId = await leftAsItWas(set, page, was, bound, "federated");
	const transaction = await openStepUp(set, page);
	const record = await steppedUp(
		set,
		page,
		sid,
		transaction,
		factorId,
		totpCodeForTests(secret, { offset: 1 }),
	);
	expect(record?.amr).toEqual(expect.arrayContaining(["otp", "mfa"]));
});

it("a first WebAuthn factor bound from the account page under never is recorded password and leaves the session as it was; the session then steps up with it", async () => {
	const set = await boot("never", webauthnMfaFactorConfigForTests({ enabled: true }));
	const page = browser();
	const sid = await passwordSignIn(set, page);
	const was = await before(set, page, sid);
	const passkey = softwarePasskey({ rpId: "auth.test", origin: ISSUER });

	const begun = await page.post(set.app, "/session/mfa/enrollment", { kind: "webauthn" });
	expect(begun.status, JSON.stringify(begun.body)).toBe(200);
	const bound = await page.post(set.app, "/session/mfa/enrollment/complete", {
		transaction_id: begun.body.transaction,
		proof: passkey.register(begun.body.challenge as string),
	});

	const factorId = await leftAsItWas(set, page, was, bound, "password");
	const transaction = await openStepUp(set, page);
	const options = await page.post(set.app, "/session/mfa/challenge", {
		transaction_id: transaction,
		factor_id: factorId,
	});
	expect(options.status, JSON.stringify(options.body)).toBe(200);
	const record = await steppedUp(
		set,
		page,
		sid,
		transaction,
		factorId,
		passkey.assert(options.body.challenge as string),
	);
	expect(record?.amr).toEqual(["pwd", "hwk", "mfa"]);
});

it("a first email factor bound from the account page under never is recorded password and leaves the session as it was; the session then steps up with it", async () => {
	const set = await boot("never", mfaEmailFactorConfigForTests({ enabled: true }));
	const page = browser();
	const sid = await passwordSignIn(set, page);
	const was = await before(set, page, sid);

	const begun = await page.post(set.app, "/session/mfa/enrollment", { kind: "email" });
	expect(begun.status, JSON.stringify(begun.body)).toBe(200);
	const bound = await page.post(set.app, "/session/mfa/enrollment/complete", {
		transaction_id: begun.body.transaction,
		proof: set.mail.sent.at(-1)?.code,
	});

	const factorId = await leftAsItWas(set, page, was, bound, "password");
	const transaction = await openStepUp(set, page);
	const challenged = await page.post(set.app, "/session/mfa/challenge", {
		transaction_id: transaction,
		factor_id: factorId,
	});
	expect(challenged.status, JSON.stringify(challenged.body)).toBe(200);
	const record = await steppedUp(set, page, sid, transaction, factorId, set.mail.sent.at(-1)?.code);
	// The email factor adds no `mfa` unless it is configured to (addsMfa).
	expect(record?.amr).toEqual(["pwd", "email"]);
});

it.each<[string, () => number | null]>([
	["answers none", () => null],
	["answers one given longer ago than its window", () => Date.now() - 3_600_000],
])(
	"a first binding whose session proof stood at its admission, and whose enrollment's read of it %s, is recorded password and leaves the session as it was; the session then steps up with the factor",
	async (_what, gone) => {
		const memory = createMemoryMfaTransactionStore();
		/** What the next reads of the session proof answer: the store's, or the proof gone. */
		const reads: ("store" | "gone")[] = [];
		const transactionStore: MfaTransactionStore = {
			...memory,
			sessionEmailProofAt: async (subject, sid, nowMs) => {
				const read = reads.shift() ?? "store";
				return read === "gone" ? gone() : memory.sessionEmailProofAt(subject, sid, nowMs);
			},
		};
		const set = await boot(
			"when-mail",
			{},
			{
				extraOverrides: () => ({ mfaTransactionStore: transactionStore }),
			},
		);
		const page = browser();
		const sid = await passwordSignIn(set, page);
		const was = await before(set, page, sid);
		// The proof is asked (a sender, an address), and given in the session.
		expect((await page.post(set.app, "/session/mfa/enrollment", { kind: "totp" })).status).toBe(
			403,
		);
		const proofTransaction = await openStepUp(set, page);
		await page.post(set.app, "/session/mfa/challenge", {
			transaction_id: proofTransaction,
			factor_id: "account-email",
		});
		const proved = await page.post(set.app, "/session/mfa/verify", {
			transaction_id: proofTransaction,
			factor_id: "account-email",
			proof: set.mail.sent.at(-1)?.code,
		});
		expect(proved.status, JSON.stringify(proved.body)).toBe(200);
		const begun = await page.post(set.app, "/session/mfa/enrollment", { kind: "totp" });
		expect(begun.status, JSON.stringify(begun.body)).toBe(200);
		const secret = fromBase32(begun.body.secret as string);

		// The completion's admission reads the proof standing; the enrollment's read finds it gone.
		reads.push("store", "gone");
		const bound = await page.post(set.app, "/session/mfa/enrollment/complete", {
			transaction_id: begun.body.transaction,
			proof: totpCodeForTests(secret),
		});

		expect(reads).toEqual([]);
		const factorId = await leftAsItWas(set, page, was, bound, "password");
		const transaction = await openStepUp(set, page);
		const record = await steppedUp(
			set,
			page,
			sid,
			transaction,
			factorId,
			totpCodeForTests(secret, { offset: 1 }),
		);
		expect(record?.amr).toEqual(["pwd", "otp", "mfa"]);
	},
);
