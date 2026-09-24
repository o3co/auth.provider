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
 * The RFC 8707 `resource` the WebAuthn grant hands `grantPolicy`, on the real
 * path: nothing between the assertion and the policy is mocked.
 *
 * A software authenticator (a P-256 key made here) signs an assertion over a
 * challenge that the module's own `POST /oauth/webauthn/authentication/options`
 * issued; `@simplewebauthn/server` verifies it; the grant handler is the one
 * `createApp` registered from `webauthnModule`, with the challenge ceremony,
 * the credential store and the policy slot wired the way a composition wires
 * them. Only the policy is a spy, because what it receives is the assertion.
 *
 * The request is the JSON body `/oauth/token` hands a grant. A passkey request
 * is always JSON: `assertion` is an object, and the token route reads forms
 * with `extended: false`, which cannot carry one. A repeated `resource` with a
 * blank entry therefore arrives as `["", "https://rs.example"]` — the same
 * array `resource=&resource=https://rs.example` becomes on a form.
 *
 * The reading of that array is core's `extractResourceParam`, the one the
 * oauth grants and `/authorize` use: the empty entries are dropped, and an
 * all-empty parameter means none was requested. This grant used to carry its
 * own copy, which kept them and forwarded a blank resource to the policy.
 */

import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import {
	createApp,
	createMemoryWebAuthnCredentialStore,
	createSymmetricKeyStore,
	defaultChallengeCeremonyModule,
	defineModule,
	type GrantContext,
	type GrantHandler,
	type GrantHandlerResolver,
	type GrantPolicyHook,
	memoryChallengeStoreModule,
	memoryReplaySeenSetModule,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import express from "express";
import supertest from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { WebAuthnConfig } from "#/config.mjs";
import { WEBAUTHN_GRANT_TYPE } from "#/grant.mjs";
import { webauthnModule } from "#/module.mjs";

const ISSUER = "https://auth.example";
const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const USER_ID = "user-resource-indicator";

// ---------------------------------------------------------------------------
// Software authenticator
// ---------------------------------------------------------------------------

/**
 * A platform authenticator reduced to what an assertion needs: one ES256 key,
 * its credential id, and a sign counter.
 *
 * The public key is handed to the store as the COSE_Key an attestation would
 * have carried (RFC 9053 §7.1.1, EC2): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`,
 * CBOR-encoded by hand because it is five fixed entries. The signature is
 * ECDSA over `authenticatorData ‖ SHA-256(clientDataJSON)` (WebAuthn §6.3.3),
 * in the DER form an authenticator returns.
 */
function createSoftwareAuthenticator() {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = publicKey.export({ format: "jwk" });
	if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
		throw new Error("P-256 public key exported without x / y");
	}
	const cosePublicKey = new Uint8Array(
		Buffer.concat([
			Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
			Buffer.from(jwk.x, "base64url"),
			Buffer.from([0x22, 0x58, 0x20]),
			Buffer.from(jwk.y, "base64url"),
		]),
	);
	const credentialId = randomBytes(16).toString("base64url");
	let signCount = 0;

	return {
		credentialId,
		cosePublicKey,
		assert(challenge: string): AuthenticationResponseJSON {
			signCount += 1;
			const clientDataJSON = Buffer.from(
				JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN, crossOrigin: false }),
			);
			// rpIdHash (32) ‖ flags (UP | UV) ‖ signCount (uint32, big-endian)
			const authenticatorData = Buffer.alloc(37);
			createHash("sha256").update(RP_ID).digest().copy(authenticatorData, 0);
			authenticatorData[32] = 0x01 | 0x04;
			authenticatorData.writeUInt32BE(signCount, 33);
			const signature = sign(
				"sha256",
				Buffer.concat([authenticatorData, createHash("sha256").update(clientDataJSON).digest()]),
				privateKey,
			);
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				response: {
					clientDataJSON: clientDataJSON.toString("base64url"),
					authenticatorData: authenticatorData.toString("base64url"),
					signature: signature.toString("base64url"),
				},
				clientExtensionResults: {},
			};
		},
	};
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

const webauthnConfig: WebAuthnConfig = {
	rpId: RP_ID,
	rpName: "Example",
	origin: [ORIGIN],
	challengeTtlMs: 120_000,
	attestationPreference: "none",
	userVerification: "preferred",
	allowCredentialsForKnownUser: false,
	rateLimit: { authenticationOptions: { limit: 1000, windowSeconds: 60 } },
};

type Handle = Awaited<ReturnType<typeof createApp>>;
const handles: Handle[] = [];

afterEach(async () => {
	await Promise.all(handles.splice(0).map((handle) => handle.dispose()));
});

/**
 * Boots `webauthnModule` with core's memory challenge store and ceremony, a
 * credential store holding the authenticator's key, the policy spy in the
 * `grantPolicy` slot, and `oauth.resourceIndicator.enabled` on — the flag
 * under which the grant forwards `resource` at all.
 */
async function boot() {
	const authenticator = createSoftwareAuthenticator();
	const credentialStore = createMemoryWebAuthnCredentialStore();
	await credentialStore.registerCredential({
		userId: USER_ID,
		credentialId: authenticator.credentialId,
		publicKey: authenticator.cosePublicKey,
		signCount: 0,
		backedUp: false,
		createdAt: new Date(),
	});

	const evaluate = vi.fn<GrantPolicyHook["evaluate"]>(async () => ({ outcome: "allow" }));
	const base = makeValidAppConfig();
	const config = {
		...base,
		// A single-replica composition: no warning about the per-process limiter.
		deployment: { mode: "single" },
		oauth: {
			...base.oauth,
			jwt: { ...base.oauth.jwt, issuer: ISSUER },
			resourceIndicator: { enabled: true },
		},
	};

	const handle = await createApp({
		modules: [
			webauthnModule,
			memoryChallengeStoreModule,
			memoryReplaySeenSetModule,
			defaultChallengeCeremonyModule,
			defineModule({
				name: "test:resource-indicator-slots",
				provides: {
					webauthnConfig: () => webauthnConfig,
					webauthnCredentialStore: () => credentialStore,
					keyStore: () => createSymmetricKeyStore("resource-indicator-secret-32-bytes!"),
					grantPolicy: (): GrantPolicyHook => ({ kind: "test-spy", evaluate }),
				},
			}),
			// Makes the planner materialise the grant registry into the handle.
			defineModule({
				name: "test:resource-indicator-activator",
				requires: ["grantHandlerResolver"] as never,
			}),
		],
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});
	handles.push(handle);

	const resolver = (handle.components as Record<string, unknown>).grantHandlerResolver as
		| GrantHandlerResolver
		| undefined;
	const registered = resolver?.get(WEBAUTHN_GRANT_TYPE) as GrantHandler | undefined;
	if (!registered) throw new Error("webauthnModule registered no grant");
	const grant: GrantHandler = registered;

	const app = express();
	app.use(handle.router);

	/** One passkey sign-in: a challenge from the real options route, then the grant. */
	async function signIn(resource: unknown) {
		const options = await supertest(app)
			.post("/oauth/webauthn/authentication/options")
			.set("Content-Type", "application/json")
			.send({});
		expect(options.status).toBe(200);
		const ctx: GrantContext = {
			body: {
				grant_type: WEBAUTHN_GRANT_TYPE,
				assertion: authenticator.assert(options.body.challenge),
				...(resource === undefined ? {} : { resource }),
			},
			session: {},
			issuer: ISSUER,
			metadata: {},
			authenticatedClient: null,
		};
		return grant.handle(ctx);
	}

	return { evaluate, signIn };
}

describe("webauthn grant — the `resource` grantPolicy receives (RFC 8707)", () => {
	it("forwards a single resource as a one-element list (the harness reaches the policy)", async () => {
		const { evaluate, signIn } = await boot();

		const { result } = await signIn("https://rs.example");

		expect(result.status).toBe(200);
		expect(evaluate).toHaveBeenCalledOnce();
		expect(evaluate.mock.calls[0]?.[0].resource).toEqual(["https://rs.example"]);
	});

	it("drops the blank entry of a repeated resource, as the oauth grants do", async () => {
		const { evaluate, signIn } = await boot();

		const { result } = await signIn(["", "https://rs.example"]);

		expect(result.status).toBe(200);
		expect(evaluate).toHaveBeenCalledOnce();
		expect(evaluate.mock.calls[0]?.[0].resource).toEqual(["https://rs.example"]);
	});

	it("reads an all-blank resource as none requested", async () => {
		const { evaluate, signIn } = await boot();

		const { result } = await signIn(["", ""]);

		expect(result.status).toBe(200);
		expect(evaluate).toHaveBeenCalledOnce();
		expect(evaluate.mock.calls[0]?.[0].resource).toBeUndefined();
	});
});
