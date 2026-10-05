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
 * The consumers of a browser session that session admission gates — device
 * approval, the federation link start, WebAuthn registration and the
 * federation-grant connect — through the full set's boot with the MFA
 * package's own requirement under `mfa.mode = "required"` and the TOTP
 * factor: each one's answer to a session the requirement steps up, the MFA
 * page's step-up and the consumer admitting the session after it, connect's
 * one trip, a dead session, an outage of the factor store the requirement
 * reads, a sign-in or a second factor older than recent MFA, the same
 * consumers with no MFA module, and what a WebAuthn registration leaves on
 * the session.
 *
 * A password session without a second factor exists under `required` only
 * when it was signed in before the deployment required MFA: those cases run
 * on two replicas sharing one Redis database, one booted `optional` and one
 * `required`. The rest run on one replica with every store in memory. Every
 * test signs in a user of its own. The MFA routes are driven through their
 * HTTP surface alone, as the MFA page drives them.
 */

import { randomBytes } from "node:crypto";
import {
	type ApproveDeviceAuthorizationInput,
	createMemoryDeviceCodeStore,
	type UserSessionStore,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import { DEVICE_CODE_GRANT_TYPE } from "@o3co/auth-provider-device-grant";
import {
	mfaConfigForTests,
	mfaTotpFactorConfigForTests,
	totpCodeForTests,
} from "@o3co/auth-provider-mfa/testing";
import {
	ALICE,
	basic,
	CONNECTION,
	ISSUER,
	MULTI_ENV,
	type Outage,
	SINGLE_ENV,
	WORKER,
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
	TV,
} from "./full-set.fixture.mts";
import { softwarePasskey } from "./software-passkey.mts";

/** The MFA page the MFA package's reference configuration registers as its step-up page. */
const MFA_PAGE = new URL("/mfa", ISSUER).href;

/** Where the template's fake Google takes an authorization request. */
const GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";

/** A user of the test's own, in the in-memory directory every replica of the boot is built with. */
interface User {
	readonly username: string;
	readonly password: string;
	readonly id: string;
}

const newUser = (): User => {
	const tag = randomBytes(6).toString("hex");
	return {
		username: `consumer-${tag}`,
		password: `password-${tag}-long`,
		id: `u-consumer-${tag}`,
	};
};

type Browser = ReturnType<typeof browser>;

type Factor = { readonly factorId: string; readonly secret: Buffer };

const booted: FullSet[] = [];

afterEach(async () => {
	vi.restoreAllMocks();
	await Promise.all(booted.splice(0).map((set) => set.handle.dispose()));
});

/** Recent MFA's window, `mfa.manage.maxAgeSeconds`, as every boot here sets it. */
const RECENT_MFA_SECONDS = 300;

/** The MFA package's configuration under `mode`, the TOTP factor on, with `extra` laid over it. */
const adjust =
	(mode: "optional" | "required", extra: Record<string, unknown> = {}) =>
	(config: Switches): Switches =>
		({
			...config,
			...mfaConfigForTests({
				key: MFA_KEY,
				mode,
				manage: { maxAgeSeconds: RECENT_MFA_SECONDS },
				...extra,
			}),
			...mfaTotpFactorConfigForTests(),
		}) as unknown as Switches;

/** Boots the full set for `users` under `required`, with `options` laid over it. */
async function boot(users: readonly User[], options: FullSetOptions = {}): Promise<FullSet> {
	const set = await composeFullSet({
		adjust: adjust("required"),
		extraUsers: Object.fromEntries(
			users.map((user) => [user.username, { id: user.id, password: user.password }]),
		),
		...options,
	});
	booted.push(set);
	return set;
}

/** The session store the full set wires. */
const sessionStoreOf = (set: FullSet): UserSessionStore =>
	(set.handle.components as unknown as { readonly userSessionStore: UserSessionStore })
		.userSessionStore;

// ---------------------------------------------------------------------------
// The browser's steps
// ---------------------------------------------------------------------------

/** A password login answered 200: no requirement interrupts it. */
async function signIn(app: Express, page: Browser, user: User): Promise<void> {
	const res = await page.post(
		app,
		"/session/login",
		{ username: user.username, password: user.password },
		{ form: true },
	);
	expect(res.status, JSON.stringify(res.body)).toBe(200);
}

/** A password login the MFA requirement interrupts, finished with the TOTP factor. */
async function signInWithFactor(
	app: Express,
	page: Browser,
	user: User,
	factor: Factor,
): Promise<void> {
	const res = await page.post(
		app,
		"/session/login",
		{ username: user.username, password: user.password },
		{ form: true },
	);
	expect(res.status, JSON.stringify(res.body)).toBe(403);
	expect(res.body.error).toBe("mfa_required");
	const verified = await page.post(app, "/session/mfa/verify", {
		transaction_id: res.body.transaction,
		factor_id: factor.factorId,
		proof: totpCodeForTests(factor.secret),
	});
	expect(verified.status, JSON.stringify(verified.body)).toBe(200);
}

/** What the MFA page does for a subject holding a counting factor: opens the step-up and verifies the TOTP code. */
async function stepUp(app: Express, page: Browser, factor: Factor): Promise<void> {
	const opened = await page.post(app, "/session/mfa/step-up", {});
	expect(opened.status, JSON.stringify(opened.body)).toBe(200);
	expect(opened.body.email_proof).toBe(false);
	const verified = await page.post(app, "/session/mfa/verify", {
		transaction_id: opened.body.transaction,
		factor_id: factor.factorId,
		proof: totpCodeForTests(factor.secret),
	});
	expect(verified.status, JSON.stringify(verified.body)).toBe(200);
	expect(verified.body).toEqual({ step_up: "verified" });
}

/** A JWT's claims, unverified: the replica signed it a line earlier. */
const claimsOf = (jwt: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(jwt.split(".")[1] as string, "base64url").toString("utf8"));

/** Waits until the wall clock is into its next second, so two instants a test compares fall in different ones. */
const nextSecond = () => new Promise((resolve) => setTimeout(resolve, 1005 - (Date.now() % 1000)));

/** The sid of the session record the next login on `set` writes, read as `run` signs in. */
async function sidOfLogin(set: FullSet, run: () => Promise<void>): Promise<string> {
	const create = vi.spyOn(sessionStoreOf(set), "create");
	await run();
	const sid = (create.mock.calls[0]?.[0] as { readonly sid?: unknown } | undefined)?.sid;
	create.mockRestore();
	if (typeof sid !== "string") throw new Error("the login created no session record");
	return sid;
}

// ---------------------------------------------------------------------------
// The consumers
// ---------------------------------------------------------------------------

/** The browser's request at a consumer, sent on `app`; `target` is the link it follows, when it was handed one. */
type Visit = ((app: Express, page: Browser) => Promise<request.Response>) & {
	readonly target?: URL;
};

/** A consumer of the browser session, and how it answers each admission. */
interface Consumer {
	readonly name: string;
	/** The grade of the action the consumer admits the session as. */
	readonly grade: "use" | "credential_change";
	/** Makes what the visit needs on `app` for `user` (a device code, a lodged grant), and answers the visit. */
	readonly arrange: (app: Express, user: User) => Promise<Visit>;
	/** Checks the consumer's step-up answer, and answers the visit the browser makes once the page is done. */
	readonly steppedUp: (res: request.Response, visit: Visit) => Visit;
	/** Checks the consumer's answer to an admitted session, and what it left for the browser on `app`. */
	readonly admitted: (res: request.Response, app: Express, page: Browser) => Promise<void>;
	/** Checks the consumer's answer to a dead session. */
	readonly dead: (res: request.Response) => void;
	/** Checks the consumer's answer to an outage. */
	readonly unavailable: (res: request.Response) => void;
}

/** The JSON `403 step_up_required` three consumers answer, naming the requirement and its page; the browser comes back to the same request. */
const jsonStepUp = (res: request.Response, visit: Visit): Visit => {
	expect(res.status, JSON.stringify(res.body)).toBe(403);
	expect(res.body).toMatchObject({ error: "step_up_required", requirement: "mfa", page: MFA_PAGE });
	return visit;
};

const jsonUnavailable = (res: request.Response): void => {
	expect(res.status, JSON.stringify(res.body)).toBe(503);
	expect(res.body.error).toBe("temporarily_unavailable");
};

const deviceApproval: Consumer = {
	name: "device approval",
	grade: "use",
	arrange: async (app) => {
		const started = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: TV.id });
		expect(started.status, JSON.stringify(started.body)).toBe(200);
		const userCode = started.body.user_code as string;
		return (on, page) =>
			page.post(on, "/oauth/device/verification", { action: "approve", user_code: userCode });
	},
	steppedUp: jsonStepUp,
	admitted: async (res) => {
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(res.body.status).toBe("approved");
	},
	dead: (res) => {
		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body.error).toBe("login_required");
	},
	unavailable: jsonUnavailable,
};

const linkStart: Consumer = {
	name: "the link start",
	grade: "credential_change",
	arrange: async () => (on, page) =>
		page.get(on, "/session/oauth/federation/google?link=1", { "Sec-Fetch-Site": "same-origin" }),
	steppedUp: jsonStepUp,
	// Google's authorization request, as the full set's fake Google answers it, for this link.
	admitted: async (res) => {
		expect(res.status, JSON.stringify(res.body)).toBe(302);
		const upstream = new URL(res.headers.location as string);
		expect(upstream.origin + upstream.pathname).toBe(GOOGLE_AUTHORIZATION_ENDPOINT);
		expect(upstream.searchParams.get("state")).toEqual(expect.any(String));
	},
	dead: (res) => {
		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body.error).toBe("login_required");
	},
	unavailable: jsonUnavailable,
};

const webauthnRegistration: Consumer = {
	name: "WebAuthn registration",
	grade: "credential_change",
	arrange: async () => (on, page) => page.post(on, "/oauth/webauthn/registration/options", {}),
	steppedUp: jsonStepUp,
	admitted: async (res) => {
		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(typeof res.body.challenge).toBe("string");
	},
	// No subject reaches the registration route: its own 401.
	dead: (res) => {
		expect(res.status, JSON.stringify(res.body)).toBe(401);
		expect(res.body.error).toBe("unauthorized");
	},
	unavailable: jsonUnavailable,
};

/** `url` read against the issuer, whose origin it must have. */
const onIssuer = (url: string): URL => {
	const parsed = new URL(url, ISSUER);
	expect(parsed.origin).toBe(ISSUER);
	return parsed;
};

const grantConnect: Consumer = {
	name: "the federation-grant connect",
	grade: "use",
	arrange: async (app, user) => {
		const lodged = await request(app)
			.post("/oauth/federation-grants")
			.set("Authorization", basic(WORKER))
			.send({
				connection: CONNECTION,
				sub: user.id,
				redirect_uri: WORKER.redirectUri,
				state: "consumer-state",
			});
		expect(lodged.status, JSON.stringify(lodged.body)).toBe(201);
		const connect = onIssuer(lodged.body.connect_uri as string);
		return Object.assign(
			(on: Express, page: Browser) => page.get(on, connect.pathname + connect.search),
			{ target: connect },
		);
	},
	// A 303 to the page, returning to this connect on the issuer with the one-trip marker on it.
	steppedUp: (res, visit) => {
		expect(res.status, res.text).toBe(303);
		const page = onIssuer(res.headers.location as string);
		expect(page.origin + page.pathname).toBe(MFA_PAGE);
		const back = page.searchParams.get("redirect_to");
		if (back === null) throw new Error(`no redirect_to on ${page.href}`);
		const marked = onIssuer(back);
		const connect = visit.target;
		if (connect === undefined) throw new Error("the connect visit names no link");
		expect(marked.pathname).toBe(connect.pathname);
		expect(marked.searchParams.get("request")).toBe(connect.searchParams.get("request"));
		expect(marked.search).not.toBe(connect.search);
		return (on, browserPage) => browserPage.get(on, marked.pathname + marked.search);
	},
	// The deployment's consent page, and the question parked there for this browser.
	admitted: async (res, on, page) => {
		expect(res.status, res.text).toBe(303);
		const consent = onIssuer(res.headers.location as string);
		expect(consent.pathname).toBe(SINGLE_ENV.FEDERATION_GRANTS_CONSENT_URL);
		const challenge = consent.searchParams.get("challenge");
		if (challenge === null) throw new Error(`no challenge on ${consent.href}`);
		const question = await page.get(
			on,
			`/session/federation-grants/consent?${new URLSearchParams({ challenge })}`,
		);
		expect(question.status, JSON.stringify(question.body)).toBe(200);
	},
	dead: (res) => {
		expect(res.status, res.text).toBe(403);
		expect(res.headers.location).toBeUndefined();
	},
	unavailable: (res) => {
		expect(res.status, res.text).toBe(503);
	},
};

const CONSUMERS: readonly Consumer[] = [
	deviceApproval,
	linkStart,
	webauthnRegistration,
	grantConnect,
];

// ---------------------------------------------------------------------------
// A session signed in before MFA was required: two replicas over Redis
// ---------------------------------------------------------------------------

let redis: TestRedis | undefined;

beforeAll(async () => {
	redis = await testRedis();
});

/**
 * Two replicas over this file's Redis database: `before`, booted under
 * `optional`, and `after`, under `required` with `options` laid over it.
 */
async function rollout(
	users: readonly User[],
	options: FullSetOptions = {},
): Promise<{ readonly before: FullSet; readonly after: FullSet }> {
	if (redis === undefined) throw new Error("no Redis database for this file");
	const url = `redis://${redis.host}:${redis.port}/${redis.db}`;
	const shared: FullSetOptions = {
		env: { ...MULTI_ENV, REDIS_CLIENTS_URL: url, SESSION_STORE_STORAGE_REDIS_URL: url },
		stores: "redis",
		shippedRefreshTokenFamilyStore: true,
	};
	const before = await boot(users, { ...shared, adjust: adjust("optional") });
	const after = await boot(users, { ...shared, ...options });
	return { before, after };
}

/**
 * `user` signed in with a password alone on `before`, while they held no
 * factor, then given a TOTP factor: a session the `required` replica steps up.
 */
async function unmetSession(
	before: FullSet,
	after: FullSet,
	user: User,
): Promise<{ readonly page: Browser; readonly factor: Factor }> {
	const page = browser();
	await signIn(before.app, page, user);
	const factor = await seedTotp(after.handle.components, after.config, user.id);
	return { page, factor };
}

describe.each(CONSUMERS)(
	"$name, for a session signed in before MFA was required (two replicas over Redis)",
	(consumer) => {
		it("answers its step-up, and admits the session once the MFA page's step-up verified the TOTP factor", async () => {
			const user = newUser();
			const { before, after } = await rollout([user]);
			const { page, factor } = await unmetSession(before, after, user);
			const visit = await consumer.arrange(after.app, user);

			const retry = consumer.steppedUp(await visit(after.app, page), visit);
			await stepUp(after.app, page, factor);

			await consumer.admitted(await retry(after.app, page), after.app, page);
		});

		it("answers 503 when the factor store the requirement reads is down, never admitting the session", async () => {
			const user = newUser();
			const outage: Outage = { down: false };
			const { before, after } = await rollout([user], {
				outage: { slot: "mfaFactorStore", outage },
			});
			const { page } = await unmetSession(before, after, user);
			const visit = await consumer.arrange(after.app, user);

			outage.down = true;
			consumer.unavailable(await visit(after.app, page));

			// Nothing was admitted or recorded: with the store back, the same visit is still stepped up.
			outage.down = false;
			consumer.steppedUp(await visit(after.app, page), visit);
		});
	},
);

describe("the federation-grant connect, for a session signed in before MFA was required (two replicas over Redis)", () => {
	it("answers the marked return of a session still unmet with a 403 and no redirect: one trip, never sent again", async () => {
		const user = newUser();
		const { before, after } = await rollout([user]);
		const { page } = await unmetSession(before, after, user);
		const visit = await grantConnect.arrange(after.app, user);
		const back = grantConnect.steppedUp(await visit(after.app, page), visit);

		grantConnect.dead(await back(after.app, page));
	});
});

// ---------------------------------------------------------------------------
// Under required, one replica in memory
// ---------------------------------------------------------------------------

describe.each(CONSUMERS)("$name, under mfa.mode = required", (consumer) => {
	it("answers a dead session — its subject's sessions revoked after a login with the TOTP factor — as a dead session", async () => {
		const user = newUser();
		const set = await boot([user]);
		const factor = await seedTotp(set.handle.components, set.config, user.id);
		const page = browser();
		await signInWithFactor(set.app, page, user, factor);
		const visit = await consumer.arrange(set.app, user);

		const revocation = set.handle.components.subjectRevocation;
		if (revocation === undefined) throw new Error("the full set wires no subject revocation");
		await revocation.revokeBefore(user.id, new Date(), new Date(Date.now() + 86_400_000));

		consumer.dead(await visit(set.app, page));
	});

	it(
		consumer.grade === "use"
			? "admits a session whose second factor was verified before mfa.manage.maxAgeSeconds: the baseline alone"
			: "steps up a session whose second factor was verified before mfa.manage.maxAgeSeconds: recent MFA",
		async () => {
			const user = newUser();
			const set = await boot([user]);
			const factor = await seedTotp(set.handle.components, set.config, user.id);
			const page = browser();
			await signInWithFactor(set.app, page, user, factor);
			const visit = await consumer.arrange(set.app, user);

			// The same session, read as if it signed in and verified its factor a minute before the window.
			readAged(set, { authTime: true, mfaAt: true });

			const res = await visit(set.app, page);
			if (consumer.grade === "use") await consumer.admitted(res, set.app, page);
			else consumer.steppedUp(res, visit);
		},
	);

	it("admits a session whose sign-in is older than mfa.manage.maxAgeSeconds and whose second factor is recent: recent MFA reads the second factor", async () => {
		const user = newUser();
		const set = await boot([user]);
		const factor = await seedTotp(set.handle.components, set.config, user.id);
		const page = browser();
		await signInWithFactor(set.app, page, user, factor);
		const visit = await consumer.arrange(set.app, user);

		// The same session, read as if it signed in a minute before the window and verified its factor now.
		readAged(set, { authTime: true, mfaAt: false });

		await consumer.admitted(await visit(set.app, page), set.app, page);
	});
});

/** Every read of a session record on `set` from here on, with the named times a minute older than recent MFA's window. */
function readAged(set: FullSet, which: { readonly authTime: boolean; readonly mfaAt: boolean }) {
	const store = sessionStoreOf(set);
	const read = store.get.bind(store);
	const aged = (at: Date) => new Date(at.getTime() - (RECENT_MFA_SECONDS + 60) * 1_000);
	vi.spyOn(store, "get").mockImplementation(async (sid) => {
		const session = await read(sid);
		if (session === null) return null;
		const authentication = session.authentication;
		const mfaAt = authentication?.mfaAt;
		return {
			...session,
			authTime: which.authTime ? aged(session.authTime) : session.authTime,
			...(authentication === undefined || mfaAt === undefined || !which.mfaAt
				? {}
				: { authentication: { ...authentication, mfaAt: aged(mfaAt) } }),
		};
	});
}

// ---------------------------------------------------------------------------
// With no MFA module
// ---------------------------------------------------------------------------

describe.each(CONSUMERS)("$name, with no MFA module (mfa.mode = off)", (consumer) => {
	it("admits a password session as it does without MFA", async () => {
		const user = newUser();
		const set = await boot([user], { features: { mfa: false }, adjust: undefined });
		const page = browser();
		await signIn(set.app, page, user);
		const visit = await consumer.arrange(set.app, user);

		await consumer.admitted(await visit(set.app, page), set.app, page);
	});
});

// ---------------------------------------------------------------------------
// What a WebAuthn registration leaves on the session
// ---------------------------------------------------------------------------

describe("a WebAuthn registration under mfa.mode = required", () => {
	/** Registers a software passkey for the signed-in browser of `subject` on `set`, and checks the store holds it for them. */
	async function register(set: FullSet, page: Browser, subject: string): Promise<void> {
		const app = set.app;
		const passkey = softwarePasskey({ rpId: "auth.test", origin: ISSUER });
		const options = await page.post(app, "/oauth/webauthn/registration/options", {});
		expect(options.status, JSON.stringify(options.body)).toBe(200);
		const registered = await page.post(app, "/oauth/webauthn/registration/verify", {
			response: passkey.register(options.body.challenge as string),
		});
		expect(registered.status, JSON.stringify(registered.body)).toBe(200);
		const credentials = (
			set.handle.components as unknown as {
				readonly webauthnCredentialStore: WebAuthnCredentialStore;
			}
		).webauthnCredentialStore;
		const held = await credentials.listByUserId(subject);
		expect(held.map((credential) => credential.credentialId)).toContain(passkey.credentialId);
	}

	it("leaves a session's second-factor time as it was: present, after a login with the TOTP factor", async () => {
		const user = newUser();
		const set = await boot([user]);
		const factor = await seedTotp(set.handle.components, set.config, user.id);
		const page = browser();
		const sid = await sidOfLogin(set, () => signInWithFactor(set.app, page, user, factor));
		const before = (await sessionStoreOf(set).get(sid))?.authentication?.mfaAt;
		expect(before).toBeInstanceOf(Date);

		await register(set, page, user.id);

		const after = await sessionStoreOf(set).get(sid);
		expect(after?.authentication?.mfaAt).toEqual(before);
	});

	it("leaves a session's second-factor time as it was: absent, after a federated login of a subject with no counting factor", async () => {
		// No account-email proof stands between this first passkey and the session.
		const set = await boot([], {
			adjust: adjust("required", { enrollment: { requireEmailProof: "never" } }),
		});
		const page = browser();
		const sid = await sidOfLogin(set, async () => {
			// The IdP says when it authenticated the user: now, as a real login's
			// id_token does; a first binding reads that as the recent primary.
			set.upstreams.oidc.idTokenClaims.auth_time = Math.floor(Date.now() / 1000);
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
		const before = await sessionStoreOf(set).get(sid);
		expect(before?.sub).toBe(ALICE.sub);
		expect(before?.authentication?.mfaAt).toBeUndefined();

		await register(set, page, ALICE.sub);

		const after = await sessionStoreOf(set).get(sid);
		expect(after).not.toBeNull();
		expect(after?.authentication?.mfaAt).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// The device token
// ---------------------------------------------------------------------------

describe("the device token, under mfa.mode = required", () => {
	/** A device authorization for the device client: its device code and the user's code. */
	async function deviceAuthorization(app: Express) {
		const started = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: TV.id });
		expect(started.status, JSON.stringify(started.body)).toBe(200);
		return {
			deviceCode: started.body.device_code as string,
			userCode: started.body.user_code as string,
		};
	}

	/** The device's one poll after the approval, answered with its tokens. */
	async function poll(app: Express, deviceCode: string): Promise<Record<string, unknown>> {
		const tokens = await request(app).post("/oauth/token").type("form").send({
			grant_type: DEVICE_CODE_GRANT_TYPE,
			client_id: TV.id,
			device_code: deviceCode,
		});
		expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
		return claimsOf(tokens.body.access_token as string);
	}

	it("carries the approving session's amr and its primary authentication time as auth_time — not the approval's instant, never after iat — and no acr", async () => {
		const user = newUser();
		const set = await boot([user]);
		const factor = await seedTotp(set.handle.components, set.config, user.id);
		const page = browser();
		const sid = await sidOfLogin(set, () => signInWithFactor(set.app, page, user, factor));
		const session = await sessionStoreOf(set).get(sid);
		if (session === null) throw new Error("the session record is gone");
		// The approval is made in a later second than the login, so auth_time tells them apart.
		await nextSecond();
		const { deviceCode, userCode } = await deviceAuthorization(set.app);
		const approvedAt = Math.floor(Date.now() / 1000);

		const approved = await page.post(set.app, "/oauth/device/verification", {
			action: "approve",
			user_code: userCode,
		});
		expect(approved.status, JSON.stringify(approved.body)).toBe(200);
		const claims = await poll(set.app, deviceCode);

		const authTime = Math.floor(session.authTime.getTime() / 1000);
		expect(claims.amr).toEqual(["pwd", "otp", "mfa"]);
		expect(claims.auth_time).toBe(authTime);
		expect(authTime).toBeLessThan(approvedAt);
		expect(claims.auth_time as number).toBeLessThanOrEqual(claims.iat as number);
		expect(claims).not.toHaveProperty("acr");
	});

	it("carries the step-up's amr and the password login's auth_time after an approval the session stepped up for, minted on another replica (two replicas over Redis)", async () => {
		const user = newUser();
		const { before, after } = await rollout([user]);
		const page = browser();
		const sid = await sidOfLogin(before, () => signIn(before.app, page, user));
		const factor = await seedTotp(after.handle.components, after.config, user.id);
		const { deviceCode, userCode } = await deviceAuthorization(after.app);
		const approve = () =>
			page.post(after.app, "/oauth/device/verification", {
				action: "approve",
				user_code: userCode,
			});
		deviceApproval.steppedUp(await approve(), approve);
		// The step-up is made in a later second than the login, so auth_time tells them apart.
		await nextSecond();
		await stepUp(after.app, page, factor);

		const approved = await approve();
		expect(approved.status, JSON.stringify(approved.body)).toBe(200);
		const claims = await poll(before.app, deviceCode);

		const session = await sessionStoreOf(before).get(sid);
		if (session === null) throw new Error("the session record is gone");
		const authTime = Math.floor(session.authTime.getTime() / 1000);
		const mfaAt = session.authentication?.mfaAt;
		expect(mfaAt).toBeInstanceOf(Date);
		expect(Math.floor((mfaAt as Date).getTime() / 1000)).toBeGreaterThan(authTime);
		// The password, then the TOTP step-up's otp and mfa.
		expect(claims.amr).toEqual(["pwd", "otp", "mfa"]);
		expect(claims.auth_time).toBe(authTime);
		expect(claims.auth_time as number).toBeLessThanOrEqual(claims.iat as number);
		expect(claims).not.toHaveProperty("acr");
	});

	it("carries neither amr nor auth_time from an approval recorded without them, as a replica of an earlier release records one", async () => {
		// The device-code store as such a replica writes to it: an approval names neither field.
		const deviceCodes = createMemoryDeviceCodeStore();
		const earlierRelease = new Proxy(deviceCodes, {
			get(target, property) {
				if (property === "approve") {
					return ({
						amr: _amr,
						authTime: _authTime,
						...earlier
					}: ApproveDeviceAuthorizationInput) => target.approve(earlier);
				}
				const value: unknown = Reflect.get(target, property, target);
				return typeof value === "function" ? value.bind(target) : value;
			},
		});
		const user = newUser();
		const set = await boot([user], { extraOverrides: () => ({ deviceCodeStore: earlierRelease }) });
		const factor = await seedTotp(set.handle.components, set.config, user.id);
		const page = browser();
		await signInWithFactor(set.app, page, user, factor);
		const { deviceCode, userCode } = await deviceAuthorization(set.app);

		const approved = await page.post(set.app, "/oauth/device/verification", {
			action: "approve",
			user_code: userCode,
		});
		expect(approved.status, JSON.stringify(approved.body)).toBe(200);
		const claims = await poll(set.app, deviceCode);

		expect(claims.sub).toBe(user.id);
		expect(claims).not.toHaveProperty("amr");
		expect(claims).not.toHaveProperty("auth_time");
	});
});
