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
 * `/authorize` sending a session to the MFA page and resuming after it,
 * through the full set's boot with the MFA package's own requirement
 * (`mfa.mode = "optional"`, the TOTP factor) and an acr that only a second
 * factor meets: the trips a request makes (a login, a step-up, consent), the
 * code and the tokens at the end of them, and where a trip ends when nothing
 * can meet the request.
 *
 * The round trips run on one replica with every store in memory and on two
 * replicas sharing one Redis database, each step on whichever replica the
 * browser reaches. Every test signs in a user of its own, so no test reads
 * what another left in the shared database. The session store that cannot
 * record a second factor is a wrapper over core's memory store, on one
 * replica.
 */

import { randomBytes } from "node:crypto";
import {
	createInMemoryUserSessionStore,
	type MfaFactorStore,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import {
	mfaConfigForTests,
	mfaTotpFactorConfigForTests,
	totpCodeForTests,
} from "@o3co/auth-provider-mfa/testing";
import { oauthConfigForTests } from "@o3co/auth-provider-oauth/testing";
import {
	basic,
	ISSUER,
	MULTI_ENV,
	PKCE,
	THIRD,
	WEB,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import type { Switches } from "@o3co/auth-provider-standalone/src/configPath.mts";
import type { Express } from "express";
import request from "supertest";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { type TestRedis, testRedis } from "../../../../packages/redis/__tests__/support/redis.mts";
import {
	browser,
	composeFullSet,
	type FullSet,
	type FullSetOptions,
	MFA_KEY,
	seedTotp,
} from "./full-set.fixture.mts";

/** The acr this deployment vouches for with a second factor, and its table. */
const ACR_MFA = "urn:o3co:acr:mfa";
const ACR_TABLE = { [ACR_MFA]: ["mfa"] };

/** A user of the test's own, in the in-memory directory every replica of the boot is built with. */
interface User {
	readonly username: string;
	readonly password: string;
	readonly id: string;
}

const newUser = (): User => {
	const tag = randomBytes(6).toString("hex");
	return { username: `step-up-${tag}`, password: `password-${tag}-long`, id: `u-step-up-${tag}` };
};

type Browser = ReturnType<typeof browser>;

const booted: FullSet[] = [];

afterEach(async () => {
	await Promise.all(booted.splice(0).map((set) => set.handle.dispose()));
});

/** The configuration every boot here runs on: MFA optional, the TOTP factor on, the acr table. */
const adjust =
	(mode: "optional" | "required") =>
	(config: Switches): Switches => {
		const oauth = (config as unknown as { oauth?: Record<string, unknown> }).oauth;
		return {
			...config,
			...mfaConfigForTests({ key: MFA_KEY, mode }),
			...mfaTotpFactorConfigForTests(),
			oauth: { ...oauth, authorize: oauthConfigForTests({ acrValues: ACR_TABLE }).oauth.authorize },
		} as unknown as Switches;
	};

/** Boots the full set for `users`, with `options` laid over this file's configuration. */
async function boot(users: readonly User[], options: FullSetOptions = {}): Promise<FullSet> {
	const set = await composeFullSet({
		adjust: adjust("optional"),
		extraUsers: Object.fromEntries(
			users.map((user) => [user.username, { id: user.id, password: user.password }]),
		),
		...options,
	});
	booted.push(set);
	return set;
}

// ---------------------------------------------------------------------------
// The browser's steps
// ---------------------------------------------------------------------------

/** The authorization request, for `client`, with `extra` parameters. */
const authorizePath = (
	extra: Record<string, string> = {},
	client: { readonly id: string; readonly redirectUri: string } = WEB,
): string =>
	`/oauth/authorize?${new URLSearchParams({
		response_type: "code",
		client_id: client.id,
		redirect_uri: client.redirectUri,
		scope: client === WEB ? "openid profile offline_access" : "openid",
		state: "step-up-state",
		nonce: "step-up-nonce",
		code_challenge: PKCE.challenge,
		code_challenge_method: "S256",
		...extra,
	})}`;

/** Where a redirect sends the browser, against the issuer. */
const locationOf = (res: request.Response): URL => {
	expect(res.status, JSON.stringify(res.body)).toBeGreaterThanOrEqual(300);
	expect(res.status).toBeLessThan(400);
	return new URL(res.headers.location as string, ISSUER);
};

/** The path and query of the request a page returns the browser to (its `redirect_to`). */
const returnOf = (page: URL): string => {
	const back = page.searchParams.get("redirect_to");
	if (back === null) throw new Error(`no redirect_to on ${page.toString()}`);
	const url = new URL(back);
	expect(url.origin).toBe(ISSUER);
	return url.pathname + url.search;
};

/** The browser at the login page: the request to come back to. */
const atLogin = (res: request.Response): string => {
	const page = locationOf(res);
	expect(page.origin + page.pathname).toBe(`${ISSUER}/login`);
	return returnOf(page);
};

/** The ask a request to come back to carries. */
const askOn = (back: string): string | null => new URL(back, ISSUER).searchParams.get("reauth_ask");

/** The browser at the MFA page: the acr hinted, and the request to come back to. */
const atMfaPage = (res: request.Response): string => {
	const page = locationOf(res);
	expect(page.origin + page.pathname).toBe(`${ISSUER}/mfa`);
	expect(page.searchParams.get("acr_values")).toBe(ACR_MFA);
	return returnOf(page);
};

/** The browser back at `client`: the redirect's parameters. */
const atClient = (
	res: request.Response,
	client: { readonly redirectUri: string } = WEB,
): URLSearchParams => {
	const back = locationOf(res);
	expect(back.origin + back.pathname).toBe(client.redirectUri);
	return back.searchParams;
};

/** A password login on `app`, answered 200. */
async function signIn(app: Express, page: Browser, user: User): Promise<void> {
	const res = await page.post(
		app,
		"/session/login",
		{ username: user.username, password: user.password },
		{ form: true },
	);
	expect(res.status, JSON.stringify(res.body)).toBe(200);
}

/** A password login the MFA requirement interrupts, finished with the TOTP factor on `verifyOn`. */
async function signInWithFactor(
	app: Express,
	page: Browser,
	user: User,
	factor: { readonly factorId: string; readonly secret: Buffer },
	offset = 0,
	verifyOn: Express = app,
): Promise<void> {
	const res = await page.post(
		app,
		"/session/login",
		{ username: user.username, password: user.password },
		{ form: true },
	);
	expect(res.status, JSON.stringify(res.body)).toBe(403);
	expect(res.body.error).toBe("mfa_required");
	const verified = await page.post(verifyOn, "/session/mfa/verify", {
		transaction_id: res.body.transaction,
		factor_id: factor.factorId,
		proof: totpCodeForTests(factor.secret, { offset }),
	});
	expect(verified.status, JSON.stringify(verified.body)).toBe(200);
}

/** What the MFA page does: opens the step-up with the acr hinted, on `openOn`, and verifies the TOTP code on `verifyOn`. */
async function stepUp(
	openOn: Express,
	verifyOn: Express,
	page: Browser,
	factor: { readonly factorId: string; readonly secret: Buffer },
	offset = 0,
): Promise<void> {
	const opened = await page.post(openOn, "/session/mfa/step-up", { acr_values: ACR_MFA });
	expect(opened.status, JSON.stringify(opened.body)).toBe(200);
	const verified = await page.post(verifyOn, "/session/mfa/verify", {
		transaction_id: opened.body.transaction,
		factor_id: factor.factorId,
		proof: totpCodeForTests(factor.secret, { offset }),
	});
	expect(verified.status, JSON.stringify(verified.body)).toBe(200);
	expect(verified.body).toEqual({ step_up: "verified" });
}

/** The code exchange for `client`. */
const redeem = (
	app: Express,
	code: string,
	client: { readonly id: string; readonly secret: string; readonly redirectUri: string } = WEB,
) =>
	request(app).post("/oauth/token").set("Authorization", basic(client)).type("form").send({
		grant_type: "authorization_code",
		code,
		redirect_uri: client.redirectUri,
		code_verifier: PKCE.verifier,
	});

/** A JWT's claims, unverified: the issuing replica signed it a line earlier. */
const claimsOf = (jwt: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString("utf8"));

/** Waits until the wall clock is into its next second, so two instants a test compares fall in different ones. */
const nextSecond = () => new Promise((resolve) => setTimeout(resolve, 1005 - (Date.now() % 1000)));

/** The components the tests read, as the full set wires them. */
const storesOf = (set: FullSet) =>
	set.handle.components as unknown as {
		readonly mfaFactorStore: MfaFactorStore;
		readonly userSessionStore: UserSessionStore;
	};

// ---------------------------------------------------------------------------
// The round trips, on memory and on two replicas over Redis
// ---------------------------------------------------------------------------

let redis: TestRedis | undefined;

beforeAll(async () => {
	redis = await testRedis();
});

/** The replicas a test talks to: one in memory, or two over this file's Redis database. */
async function replicas(
	stores: "memory" | "redis",
	users: readonly User[],
): Promise<readonly [FullSet, FullSet]> {
	if (stores === "memory") {
		const set = await boot(users);
		return [set, set];
	}
	if (redis === undefined) throw new Error("no Redis database for this file");
	const url = `redis://${redis.host}:${redis.port}/${redis.db}`;
	const options: FullSetOptions = {
		env: { ...MULTI_ENV, REDIS_CLIENTS_URL: url, SESSION_STORE_STORAGE_REDIS_URL: url },
		stores: "redis",
		shippedRefreshTokenFamilyStore: true,
	};
	return [await boot(users, options), await boot(users, options)];
}

describe.each(["memory", "redis"] as const)("the step-up round trip, stores in %s", (stores) => {
	it("acr_values: the MFA page, the step-up, back, a code, and tokens carrying the step-up's amr, the acr and the primary's auth_time", async () => {
		const user = newUser();
		const [a, b] = await replicas(stores, [user]);
		const page = browser();
		const create = vi.spyOn(storesOf(a).userSessionStore, "create");
		await signIn(a.app, page, user);
		const created = create.mock.calls[0]?.[0] as { readonly sid: string } | undefined;
		if (created === undefined) throw new Error("the login created no session record");
		create.mockRestore();
		const factor = await seedTotp(a.handle.components, a.config, user.id);
		// The step-up is made in a later second than the login, so auth_time tells them apart.
		await nextSecond();

		const back = atMfaPage(await page.get(a.app, authorizePath({ acr_values: ACR_MFA })));
		await stepUp(b.app, a.app, page, factor);
		const code = atClient(await page.get(b.app, back)).get("code") as string;

		const tokens = await redeem(a.app, code);
		expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
		const session = await storesOf(b).userSessionStore.get(created.sid);
		if (session === null) throw new Error("the session record is gone");
		const authTime = Math.floor(session.authTime.getTime() / 1000);
		const mfaAt = session.authentication?.mfaAt;
		expect(mfaAt).toBeInstanceOf(Date);
		expect(Math.floor((mfaAt as Date).getTime() / 1000)).toBeGreaterThan(authTime);
		for (const token of [tokens.body.id_token, tokens.body.access_token] as string[]) {
			expect(claimsOf(token)).toMatchObject({
				amr: ["pwd", "otp", "mfa"],
				acr: ACR_MFA,
				auth_time: authTime,
			});
		}
	});

	it("prompt=login, acr_values and a client that asks for consent: the login trip, the step-up trip and consent, then one code", async () => {
		const user = newUser();
		const [a, b] = await replicas(stores, [user]);
		const page = browser();
		await signIn(a.app, page, user);

		const afterLogin = atLogin(
			await page.get(a.app, authorizePath({ prompt: "login", acr_values: ACR_MFA }, THIRD)),
		);
		expect(askOn(afterLogin)).toBeTruthy();
		await signIn(b.app, page, user);
		// A factor of the user's from here on: the step-up has one to verify.
		const factor = await seedTotp(b.handle.components, b.config, user.id);
		const afterStepUp = atMfaPage(await page.get(a.app, afterLogin));
		await stepUp(a.app, b.app, page, factor);

		const consent = locationOf(await page.get(b.app, afterStepUp));
		expect(consent.pathname).toBe("/consent");
		const answered = await page.post(a.app, "/oauth/consent", {
			challenge: consent.searchParams.get("challenge"),
			decision: "accept",
		});
		expect(answered.status, JSON.stringify(answered.body)).toBe(303);
		const resumed = locationOf(answered);
		expect(resumed.searchParams.get("reauth_ask")).toBe(askOn(afterStepUp));
		const code = atClient(await page.get(b.app, resumed.pathname + resumed.search), THIRD).get(
			"code",
		) as string;
		const tokens = await redeem(a.app, code, THIRD);
		expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
		expect(claimsOf(tokens.body.id_token as string)).toMatchObject({
			amr: ["pwd", "otp", "mfa"],
			acr: ACR_MFA,
		});
	});

	it("max_age and acr_values: a login trip for the stale session, then the step-up trip, then a code", async () => {
		const user = newUser();
		const [a, b] = await replicas(stores, [user]);
		const page = browser();
		await signIn(a.app, page, user);
		// max_age=0 finds a session stale once a second has turned since its login.
		await nextSecond();

		const afterLogin = atLogin(
			await page.get(b.app, authorizePath({ max_age: "0", acr_values: ACR_MFA })),
		);
		expect(askOn(afterLogin)).toBeTruthy();
		await signIn(a.app, page, user);
		const factor = await seedTotp(a.handle.components, a.config, user.id);
		const afterStepUp = atMfaPage(await page.get(b.app, afterLogin));
		await stepUp(b.app, a.app, page, factor);
		// max_age=0 is met by the login this request asked for, which the step-up's ask carries.
		const code = atClient(await page.get(a.app, afterStepUp)).get("code") as string;
		expect((await redeem(b.app, code)).status).toBe(200);
	});

	it("max_age running out during the step-up: a login trip, which carries the factor, then a code and no second step-up", async () => {
		const user = newUser();
		const [a, b] = await replicas(stores, [user]);
		const page = browser();
		await signIn(a.app, page, user);
		const factor = await seedTotp(a.handle.components, a.config, user.id);

		const afterStepUp = atMfaPage(
			await page.get(a.app, authorizePath({ max_age: "5", acr_values: ACR_MFA })),
		);
		await stepUp(b.app, a.app, page, factor);
		// The page takes longer than max_age.
		await new Promise((resolve) => setTimeout(resolve, 6_100));
		const afterLogin = atLogin(await page.get(b.app, afterStepUp));
		expect(askOn(afterLogin)).toBeTruthy();
		// The login this user makes now is interrupted for the factor, a step later than the step-up's.
		await signInWithFactor(a.app, page, user, factor, 1, b.app);
		const code = atClient(await page.get(a.app, afterLogin)).get("code") as string;
		expect((await redeem(b.app, code)).status).toBe(200);
	});
});

// ---------------------------------------------------------------------------
// A session store that cannot record a second factor
// ---------------------------------------------------------------------------

/** Core's memory session store, less the capability to record a second factor on a session. */
function withoutSecondFactor(store: UserSessionStore): UserSessionStore {
	return new Proxy(store, {
		get(target, property) {
			if (property === "recordSecondFactor") return undefined;
			const value: unknown = Reflect.get(target, property, target);
			return typeof value === "function" ? value.bind(target) : value;
		},
		has: (target, property) => property !== "recordSecondFactor" && Reflect.has(target, property),
	});
}

describe("acr_values onto a session store that cannot record a second factor", () => {
	const bootWithout = (users: readonly User[]) =>
		boot(users, {
			extraOverrides: () => ({
				userSessionStore: withoutSecondFactor(createInMemoryUserSessionStore()),
			}),
		});

	it("sends the browser to log in, and the login that carries the factor gets the code", async () => {
		const user = newUser();
		const set = await bootWithout([user]);
		const page = browser();
		await signIn(set.app, page, user);
		const factor = await seedTotp(set.handle.components, set.config, user.id);

		const back = atLogin(await page.get(set.app, authorizePath({ acr_values: ACR_MFA })));
		await signInWithFactor(set.app, page, user, factor);
		const code = atClient(await page.get(set.app, back)).get("code") as string;
		const tokens = await redeem(set.app, code);
		expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
		expect(claimsOf(tokens.body.id_token as string)).toMatchObject({ acr: ACR_MFA });
	});

	it("refuses with unmet_authentication_requirements once the login it sent the browser to carried no factor, rather than sending it again", async () => {
		// A password subject with no factor under `optional`: a new login cannot carry one.
		const user = newUser();
		const set = await bootWithout([user]);
		const page = browser();
		await signIn(set.app, page, user);

		const back = atLogin(await page.get(set.app, authorizePath({ acr_values: ACR_MFA })));
		await signIn(set.app, page, user);
		const answer = atClient(await page.get(set.app, back));
		expect(answer.get("error")).toBe("unmet_authentication_requirements");
		expect(answer.get("state")).toBe("step-up-state");
	});

	it("refuses a federated session the same way after its login trip", async () => {
		const set = await bootWithout([]);
		const page = browser();
		const federatedLogin = async () => {
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
		};
		await federatedLogin();

		const back = atLogin(await page.get(set.app, authorizePath({ acr_values: ACR_MFA })));
		await federatedLogin();
		expect(atClient(await page.get(set.app, back)).get("error")).toBe(
			"unmet_authentication_requirements",
		);
	});

	it("answers prompt=none with login_required and leaves the session signed in", async () => {
		const user = newUser();
		const set = await bootWithout([user]);
		const page = browser();
		await signIn(set.app, page, user);

		const silent = atClient(
			await page.get(set.app, authorizePath({ prompt: "none", acr_values: ACR_MFA })),
		);
		expect(silent.get("error")).toBe("login_required");
		expect(atClient(await page.get(set.app, authorizePath())).get("code")).toBeTruthy();
	});
});

// ---------------------------------------------------------------------------
// What a session from before MFA became required is answered with
// ---------------------------------------------------------------------------

describe("a session signed in while MFA was optional, after a replica requires it (two replicas over Redis)", () => {
	it("the session grant answers step_up; the refresh token minted then is refused, naming the requirement", async () => {
		if (redis === undefined) throw new Error("no Redis database for this file");
		const user = newUser();
		const url = `redis://${redis.host}:${redis.port}/${redis.db}`;
		const options: FullSetOptions = {
			env: { ...MULTI_ENV, REDIS_CLIENTS_URL: url, SESSION_STORE_STORAGE_REDIS_URL: url },
			stores: "redis",
			shippedRefreshTokenFamilyStore: true,
		};
		const before = await boot([user], options);
		const after = await boot([user], { ...options, adjust: adjust("required") });
		const page = browser();
		await signIn(before.app, page, user);
		const code = atClient(await page.get(before.app, authorizePath())).get("code") as string;
		const tokens = await redeem(before.app, code);
		expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
		expect(claimsOf(tokens.body.access_token as string).amr).toEqual(["pwd"]);
		await seedTotp(after.handle.components, after.config, user.id);

		const csrf = await page.get(after.app, "/session/csrf");
		const sessionGrant = await request(after.app)
			.post("/oauth/token")
			.set("Cookie", page.cookies().join("; "))
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.set("Authorization", basic(WEB))
			.type("form")
			.send({ grant_type: "session", scope: "openid" });
		expect(sessionGrant.status, JSON.stringify(sessionGrant.body)).toBe(400);
		expect(sessionGrant.body).toMatchObject({ error: "invalid_grant", step_up: expect.anything() });

		const refreshed = await request(after.app)
			.post("/oauth/token")
			.set("Authorization", basic(WEB))
			.type("form")
			.send({ grant_type: "refresh_token", refresh_token: tokens.body.refresh_token });
		expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(400);
		expect(refreshed.body).toMatchObject({
			error: "invalid_grant",
			error_description: "the refresh token does not meet the mfa requirement",
		});
	});
});
