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
 * The passwordless grant's assertion and its user handle, through the full
 * set's boot. The grant and the WebAuthn second factor share the relying
 * party's id, so one authenticator credential can be presented to both, and a
 * `none` attestation made from a second factor's credential id and public key
 * registers it as another account's passkey. The grant refuses an assertion
 * whose user handle is not that of the account its record belongs to
 * (WebAuthn §7.2 step 6), so the second factor's owner is not signed in as
 * that account.
 */

import type { AppConfig, AuditEvent, AuditSink, MfaFactorStore } from "@o3co/auth-provider-core";
import { seedMfaFactor } from "@o3co/auth-provider-mfa/testing";
import {
	ALICE,
	basic,
	ISSUER,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { WEBAUTHN_GRANT_TYPE } from "@o3co/auth-provider-webauthn";
import {
	webauthnMfaFactorConfigForTests,
	webauthnMfaFactorDataForTests,
} from "@o3co/auth-provider-webauthn/testing";
import type { Express } from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { browser, composeFullSet, type FullSet } from "./full-set.fixture.mts";
import { type SoftwarePasskey, softwarePasskey } from "./software-passkey.mts";

/** An account of the Store's beside the fixture's, signing in with a password. */
const MALLORY = { username: "mallory", password: "mallory-password-long", sub: "u-mallory" };

/** A confidential client that signs users in with a passkey. */
const PASSKEY_APP = { id: "passkey-app", secret: "passkey-app-secret" } as const;

/** alice's WebAuthn user handle as her second factor's enrollment made it: 32 random bytes, base64url. */
const ALICE_MFA_HANDLE = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString(
	"base64url",
);

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** An audit sink that keeps what it is handed, oldest first. */
function recordingAuditSink(): AuditSink & { readonly events: AuditEvent[] } {
	const events: AuditEvent[] = [];
	return {
		kind: "recording",
		events,
		async record(event) {
			events.push(event);
		},
	};
}

/**
 * The full set with the WebAuthn second factor on, mallory in the Store, the passkey client, and
 * a recording audit sink.
 */
async function boot(): Promise<{
	readonly app: Express;
	readonly set: FullSet;
	readonly audit: AuditEvent[];
}> {
	const audit = recordingAuditSink();
	current = await composeFullSet({
		adjust: (config) =>
			({ ...config, ...webauthnMfaFactorConfigForTests({ enabled: true }) }) as AppConfig,
		extraOverrides: () => ({ auditSink: audit }),
		extraUsers: { [MALLORY.username]: { id: MALLORY.sub, password: MALLORY.password } },
		extraClients: {
			[PASSKEY_APP.id]: {
				tokenEndpointAuthMethod: "client_secret_basic",
				clientSecret: PASSKEY_APP.secret,
				allowedScopes: ["openid"],
				defaultScopes: ["openid"],
				allowedGrantTypes: [WEBAUTHN_GRANT_TYPE],
			},
		},
	});
	return { app: current.app, set: current, audit: audit.events };
}

/** A software passkey for the full set's relying party (`auth.test`, the issuer's origin): a synced one. */
const passkeyFor = (): SoftwarePasskey =>
	softwarePasskey({ rpId: "auth.test", origin: ISSUER, backedUp: true });

/** Seeds `passkey` as alice's WebAuthn second factor, under her WebAuthn user handle. */
async function seedAliceFactor(set: FullSet, passkey: SoftwarePasskey): Promise<void> {
	const factorStore = (set.handle.components as { readonly mfaFactorStore?: MfaFactorStore })
		.mfaFactorStore;
	if (factorStore === undefined) throw new Error("the full set holds no MFA factor store");
	await seedMfaFactor({
		config: set.config,
		factorStore,
		subject: ALICE.sub,
		...webauthnMfaFactorDataForTests({
			credentialId: passkey.credentialId,
			publicKey: passkey.publicKey,
			userHandle: ALICE_MFA_HANDLE,
			backupEligible: passkey.backupEligible,
			backedUp: passkey.backedUp,
		}),
	});
}

/**
 * mallory signed in with her password registers `passkey` as her passkey: the
 * registration's answer, and the user handle its options named.
 */
async function registerAsMallory(
	app: Express,
	passkey: SoftwarePasskey,
): Promise<{ readonly registered: request.Response; readonly userHandle: string }> {
	const page = browser();
	const login = await page.post(app, "/session/login", {
		username: MALLORY.username,
		password: MALLORY.password,
	});
	expect(login.status, JSON.stringify(login.body)).toBe(200);
	const options = await page.post(app, "/oauth/webauthn/registration/options", {});
	expect(options.status, JSON.stringify(options.body)).toBe(200);
	const registered = await page.post(app, "/oauth/webauthn/registration/verify", {
		response: passkey.register(options.body.challenge as string),
	});
	return { registered, userHandle: options.body.user.id as string };
}

/** A passkey sign-in at `/oauth/token`: `passkey` asserts over a fresh challenge, answering `userHandle`. */
async function signIn(
	app: Express,
	passkey: SoftwarePasskey,
	userHandle: string,
): Promise<request.Response> {
	const options = await request(app).post("/oauth/webauthn/authentication/options").send({});
	expect(options.status).toBe(200);
	return request(app)
		.post("/oauth/token")
		.set("Authorization", basic(PASSKEY_APP))
		.send({
			grant_type: WEBAUTHN_GRANT_TYPE,
			assertion: passkey.assert(options.body.challenge as string, { userHandle }),
		});
}

const subjectOf = (accessToken: string): unknown =>
	JSON.parse(Buffer.from(accessToken.split(".")[1] as string, "base64url").toString("utf8")).sub;

/**
 * alice's second factor registered as mallory's passkey by its id and public key, then asserted
 * by alice's authenticator with her user handle: the sign-in's answer, and the audit events.
 */
async function aliceAssertsHerFactorAsMallorys(): Promise<{
	readonly res: request.Response;
	readonly audit: AuditEvent[];
}> {
	const { app, set, audit } = await boot();
	const alicePasskey = passkeyFor();
	await seedAliceFactor(set, alicePasskey);
	const { registered } = await registerAsMallory(app, alicePasskey);
	expect(registered.status, JSON.stringify(registered.body)).toBe(200);
	return { res: await signIn(app, alicePasskey, ALICE_MFA_HANDLE), audit };
}

describe("the passwordless grant's assertion and its user handle", () => {
	it("refuses alice's second factor, registered as mallory's passkey by its id and public key, when her authenticator answers with her user handle: 400 invalid_grant user_handle_mismatch, no token for mallory", async () => {
		const { res } = await aliceAssertsHerFactorAsMallorys();

		expect(res.status, JSON.stringify(res.body)).toBe(400);
		expect(res.body).toEqual({ error: "invalid_grant", error_description: "user_handle_mismatch" });
	});

	it("audits that refusal as token.issued.failure with reason user_handle_mismatch", async () => {
		const { audit } = await aliceAssertsHerFactorAsMallorys();

		const failures = audit.filter((event) => event.type === "token.issued.failure");
		expect(failures).toHaveLength(1);
		expect(failures[0]?.details).toMatchObject({
			grant_type: WEBAUTHN_GRANT_TYPE,
			error: "invalid_grant",
			reason: "user_handle_mismatch",
		});
	});

	it("signs mallory in with her own passkey when it answers with the user handle her registration options named", async () => {
		const { app } = await boot();
		const own = passkeyFor();
		const { registered, userHandle } = await registerAsMallory(app, own);
		expect(registered.status, JSON.stringify(registered.body)).toBe(200);

		const res = await signIn(app, own, userHandle);

		expect(res.status, JSON.stringify(res.body)).toBe(200);
		expect(subjectOf(res.body.access_token as string)).toBe(MALLORY.sub);
	});

	it("refuses mallory's own passkey answering her userId as raw text, as a client before @simplewebauthn/browser v10 does: 400 invalid_grant user_handle_mismatch", async () => {
		const { app } = await boot();
		const own = passkeyFor();
		const { registered } = await registerAsMallory(app, own);
		expect(registered.status, JSON.stringify(registered.body)).toBe(200);

		const res = await signIn(app, own, MALLORY.sub);

		expect(res.status, JSON.stringify(res.body)).toBe(400);
		expect(res.body).toEqual({ error: "invalid_grant", error_description: "user_handle_mismatch" });
	});
});
